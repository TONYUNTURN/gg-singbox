package proxy

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/mzz2017/gg/dialer"
	"github.com/mzz2017/gg/infra/ip_mtu_trie"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	DefaultNatTimeout = 3 * time.Minute
	DnsQueryTimeout   = 17 * time.Second // RFC 5452
)

type HijackResp struct {
	Resp   []byte
	Domain string
	Type   dnsmessage.Type
	AnsIP  netip.Addr
}

func (p *Proxy) handleUDP(lAddr net.Addr, data []byte) (err error) {
	udpAddr, ok := lAddr.(*net.UDPAddr)
	if !ok || udpAddr == nil {
		return fmt.Errorf("invalid UDP source address: %v", lAddr)
	}
	loopback, ok := netip.AddrFromSlice(udpAddr.IP)
	if !ok {
		return fmt.Errorf("invalid UDP source IP: %v", udpAddr.IP)
	}
	tgt := p.GetProjection(loopback)
	if tgt == "" {
		return fmt.Errorf("mapped target address not found: %v", loopback)
	}
	p.log.Tracef("received udp: %v, tgt: %v", lAddr.String(), tgt)
	if hijackResp, isDNSQuery := p.hijackDNS(data); isDNSQuery {
		if hijackResp != nil {
			switch hijackResp.Type {
			case dnsmessage.TypeAAAA:
				// TODO: support to restore INET6 ICMP target
				_, err = p.writeToClient(hijackResp.Resp, lAddr)
				return err
			case dnsmessage.TypeA:
				respData, respMsg, e := p.forwardDNSMessage(tgt, data)
				if e != nil {
					p.log.Tracef("will not restore INET4 ICMP target: forwardDNSMessage: %v", e)
					_, err = p.writeToClient(hijackResp.Resp, lAddr)
					return err
				}
				if len(respMsg.Answers) == 0 {
					// no answer
					p.log.Tracef("tgt dns response with no answer")
					_, err = p.writeToClient(respData, lAddr)
					return err
				}
				// we only pick the first A answer
				var realAnsA *dnsmessage.AResource
				for _, ans := range respMsg.Answers {
					A, okA := ans.Body.(*dnsmessage.AResource)
					if okA {
						realAnsA = A
						break
					}
				}
				if realAnsA == nil {
					// not a valid answer
					p.log.Tracef("tgt dns response is not valid: %v", respMsg.Answers)
				} else {
					ip := netip.AddrFrom4(realAnsA.A)
					p.realIPMapper.Set(hijackResp.AnsIP, ip)
					p.log.Tracef("fakeIP:(%v) realIP:(%v)", hijackResp.AnsIP, ip)
				}
				_, err = p.writeToClient(hijackResp.Resp, lAddr)
				return err
			}
			// TODO: try to send from original address if the socket uses bind.
			// 		But to archive it, we need bind permission.
			//		Is it worth it?
		}
		// is other DNS request type
		if d, ok := p.dialer.(*dialer.Dialer); ok && !d.SupportUDP() {
			// bypass
			respData, _, err := p.forwardDNSMessage(tgt, data)
			if err != nil {
				return fmt.Errorf("forwardDNSMessage: %w", err)
			}
			_, err = p.writeToClient(respData, lAddr)
			return err
		}
		// continue to forward DNS request but use replaced DNS server.
		tgt = "1.1.1.1:53"
	}
	if d, ok := p.dialer.(*dialer.Dialer); ok && !d.SupportUDP() {
		return fmt.Errorf("receive an unexpected UDP request to target %v: dialer does not support UDP", tgt)
	}
	targetAddr, err := net.ResolveUDPAddr("udp", tgt)
	if err != nil {
		return err
	}
	rc, session, connIdent, err := p.getOrBuildUDPConn(lAddr, tgt, targetAddr, data)
	if err != nil {
		return fmt.Errorf("auth fail from: %v: %w", lAddr.String(), err)
	}
	//p.log.Tracef("writeto: %v, %v", targetAddr, data)
	var n int
	if n, err = rc.WriteTo(data, targetAddr); err != nil {
		p.nm.RemoveIf(connIdent, session)
		return fmt.Errorf("write error: %w", err)
	}
	if n != len(data) {
		p.nm.RemoveIf(connIdent, session)
		return fmt.Errorf("write error: %w", io.ErrShortWrite)
	}
	return nil
}

func (p *Proxy) hijackDNS(data []byte) (resp *HijackResp, isDNSQuery bool) {
	var dmsg dnsmessage.Message
	if dmsg.Unpack(data) != nil {
		return nil, false
	}
	if len(dmsg.Questions) == 0 {
		return nil, true
	}
	// we only peek the first question.
	// see https://stackoverflow.com/questions/4082081/requesting-a-and-aaaa-records-in-single-dns-query/4083071#4083071
	q := dmsg.Questions[0]
	var domain string
	var ans netip.Addr
	switch q.Type {
	case dnsmessage.TypeAAAA:
		domain = strings.TrimSuffix(q.Name.String(), ".")
		ans = p.AllocProjection(domain)
		// 6in4
		dmsg.Answers = []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{
				Name:  q.Name,
				Class: q.Class,
				TTL:   10,
			},
			Body: &dnsmessage.AAAAResource{AAAA: ans.As16()},
		}}
	case dnsmessage.TypeA:
		domain = strings.TrimSuffix(q.Name.String(), ".")
		ans = p.AllocProjection(domain)
		dmsg.Answers = []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{
				Name:  q.Name,
				Class: q.Class,
				TTL:   10,
			},
			Body: &dnsmessage.AResource{A: ans.As4()},
		}}
	}
	switch q.Type {
	case dnsmessage.TypeA, dnsmessage.TypeAAAA:
		p.log.Tracef("hijackDNS: lookup: %v to %v", q.Name.String(), ans.String())
		dmsg.RCode = dnsmessage.RCodeSuccess
		dmsg.Response = true
		dmsg.RecursionAvailable = true
		dmsg.Truncated = false
		b, _ := dmsg.Pack()
		return &HijackResp{
			Resp:   b,
			Domain: domain,
			Type:   q.Type,
			AnsIP:  ans,
		}, true
	}
	return nil, true
}

// SelectTimeout selects an appropriate timeout for UDP packet.
func SelectTimeout(packet []byte) time.Duration {
	var dMessage dnsmessage.Message
	if err := dMessage.Unpack(packet); err != nil {
		return DefaultNatTimeout
	}
	return DnsQueryTimeout
}

// selectTimeout selects an appropriate timeout for UDP packet.
// With sing-box, UDP packets are already decrypted, so we just check the DNS payload directly.
func selectTimeout(packet []byte) time.Duration {
	return SelectTimeout(packet)
}

// GetOrBuildUDPConn get a UDP conn from the mapping.
func (p *Proxy) GetOrBuildUDPConn(lAddr net.Addr, target string, data []byte) (rc net.PacketConn, err error) {
	targetAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return nil, err
	}
	rc, _, _, err = p.getOrBuildUDPConn(lAddr, target, targetAddr, data)
	return rc, err
}

func (p *Proxy) getOrBuildUDPConn(lAddr net.Addr, target string, targetAddr *net.UDPAddr, data []byte) (net.PacketConn, *UDPConn, string, error) {
	connIdent := lAddr.String()
	p.nm.Lock()
	conn, exists := p.nm.Get(connIdent)
	if !exists {
		conn = p.nm.Insert(connIdent, nil)
	} else {
		conn.waiters++
	}
	p.nm.Unlock()

	if exists {
		select {
		case <-conn.Establishing:
		case <-p.closed:
			p.decrementUDPWaiter(conn)
			return nil, conn, connIdent, ErrProxyClosed
		}
		p.decrementUDPWaiter(conn)
		if conn.Err != nil {
			return nil, conn, connIdent, conn.Err
		}
		if conn.PacketConn == nil {
			return nil, conn, connIdent, errors.New("UDP session initialized without a connection")
		}
		if err := conn.PacketConn.SetReadDeadline(time.Now().Add(conn.Timeout)); err != nil {
			p.nm.RemoveIf(connIdent, conn)
			return nil, conn, connIdent, fmt.Errorf("set UDP session deadline: %w", err)
		}
		return conn.PacketConn, conn, connIdent, nil
	}

	p.lifecycleMu.Lock()
	if p.closing {
		p.lifecycleMu.Unlock()
		p.failUDPInitialization(connIdent, conn, ErrProxyClosed)
		return nil, conn, connIdent, ErrProxyClosed
	}
	p.wg.Add(1)
	p.lifecycleMu.Unlock()
	relayOwnsRegistration := false
	defer func() {
		if !relayOwnsRegistration {
			p.wg.Done()
		}
	}()

	c, err := p.dialContext(p.ctx, "udp", target)
	if err != nil {
		err = fmt.Errorf("GetOrBuildUDPConn dial error: %w", err)
		p.failUDPInitialization(connIdent, conn, err)
		return nil, conn, connIdent, err
	}
	rc, ok := c.(net.PacketConn)
	if !ok {
		_ = c.Close()
		err = errors.New("GetOrBuildUDPConn dial result does not implement net.PacketConn")
		p.failUDPInitialization(connIdent, conn, err)
		return nil, conn, connIdent, err
	}

	p.lifecycleMu.Lock()
	if p.closing {
		p.lifecycleMu.Unlock()
		_ = rc.Close()
		p.failUDPInitialization(connIdent, conn, ErrProxyClosed)
		return nil, conn, connIdent, ErrProxyClosed
	}
	p.lifecycleMu.Unlock()

	p.nm.Lock()
	current, currentExists := p.nm.Get(connIdent)
	if !currentExists || current != conn {
		p.nm.Unlock()
		_ = rc.Close()
		conn.close(ErrProxyClosed)
		return nil, conn, connIdent, ErrProxyClosed
	}
	conn.Timeout = p.udpTTL(data)
	conn.Target = targetAddr
	conn.PacketConn = rc
	close(conn.Establishing)
	p.nm.Unlock()

	if err := rc.SetReadDeadline(time.Now().Add(conn.Timeout)); err != nil {
		p.nm.RemoveIf(connIdent, conn)
		return nil, conn, connIdent, fmt.Errorf("set UDP session deadline: %w", err)
	}
	relayOwnsRegistration = true
	go func() {
		defer p.wg.Done()
		if e := p.relayUDPTo(lAddr, rc, targetAddr, conn.Timeout); e != nil && !errors.Is(e, net.ErrClosed) {
			p.log.Tracef("shadowsocks.udp.relay: %v", e)
		}
		p.nm.RemoveIf(connIdent, conn)
	}()
	return rc, conn, connIdent, nil
}

func (p *Proxy) decrementUDPWaiter(conn *UDPConn) {
	p.nm.Lock()
	conn.waiters--
	p.nm.Unlock()
}

func (p *Proxy) failUDPInitialization(connIdent string, conn *UDPConn, err error) {
	p.nm.Lock()
	current, ok := p.nm.Get(connIdent)
	if ok && current == conn {
		delete(p.nm.nm, connIdent)
	}
	conn.close(err)
	p.nm.Unlock()
}

func (p *Proxy) relayUDP(laddr net.Addr, rConn net.PacketConn, timeout time.Duration) error {
	var target net.Addr
	if conn, ok := rConn.(interface{ RemoteAddr() net.Addr }); ok {
		target = conn.RemoteAddr()
	}
	return p.relayUDPTo(laddr, rConn, target, timeout)
}

func (p *Proxy) relayUDPTo(laddr net.Addr, rConn net.PacketConn, target net.Addr, timeout time.Duration) (err error) {
	buf := make([]byte, ip_mtu_trie.MTU)
	if err := rConn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("rConn.SetReadDeadline: %w", err)
	}
	var n int
	for {
		p.log.Tracef("readfrom...")
		var source net.Addr
		n, source, err = rConn.ReadFrom(buf)
		if err != nil {
			return fmt.Errorf("rConn.ReadFrom: %w", err)
		}
		if n < 0 || n > len(buf) {
			return fmt.Errorf("rConn.ReadFrom: invalid length %d", n)
		}
		if target != nil && !sameUDPAddress(source, target) {
			continue
		}
		p.log.Tracef("readfrom: %v", buf[:n])
		//var dmsg dnsmessage.Message
		//if err := dmsg.Unpack(buf[:n]); err == nil {
		//	p.log.Traceln(dmsg)
		//}
		udpConn := p.packetConn()
		if udpConn == nil {
			return ErrProxyClosed
		}
		if err = udpConn.SetWriteDeadline(time.Now().Add(DefaultNatTimeout)); err != nil {
			return fmt.Errorf("set proxy UDP write deadline: %w", err)
		}
		var written int
		written, err = udpConn.WriteTo(buf[:n], laddr)
		if err != nil {
			return
		}
		if written != n {
			return io.ErrShortWrite
		}
		if err = rConn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return fmt.Errorf("rConn.SetReadDeadline: %w", err)
		}
	}
}

func (p *Proxy) writeToClient(data []byte, addr net.Addr) (int, error) {
	conn := p.packetConn()
	if conn == nil {
		return 0, ErrProxyClosed
	}
	return conn.WriteTo(data, addr)
}

func sameUDPAddress(a, b net.Addr) bool {
	aUDP, aOK := a.(*net.UDPAddr)
	bUDP, bOK := b.(*net.UDPAddr)
	if aOK && bOK {
		return aUDP.Port == bUDP.Port && aUDP.Zone == bUDP.Zone && aUDP.IP.Equal(bUDP.IP)
	}
	return a != nil && b != nil && a.Network() == b.Network() && a.String() == b.String()
}

func forwardDNSMessage(tgt string, msg []byte) ([]byte, *dnsmessage.Message, error) {
	return forwardDNSMessageWithTimeout(tgt, msg, DnsQueryTimeout)
}

func (p *Proxy) forwardDNSMessage(tgt string, msg []byte) ([]byte, *dnsmessage.Message, error) {
	return forwardDNSMessageWithDial(tgt, msg, DnsQueryTimeout, func(network, address string, timeout time.Duration) (net.Conn, error) {
		return p.dialTracked(p.ctx, network, address, timeout)
	})
}

func forwardDNSMessageWithTimeout(tgt string, msg []byte, timeout time.Duration) ([]byte, *dnsmessage.Message, error) {
	return forwardDNSMessageWithDial(tgt, msg, timeout, net.DialTimeout)
}

func forwardDNSMessageWithDial(tgt string, msg []byte, timeout time.Duration, dial func(string, string, time.Duration) (net.Conn, error)) ([]byte, *dnsmessage.Message, error) {
	conn, err := dial("udp", tgt, timeout)
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()
	if err = conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, nil, err
	}
	written, err := conn.Write(msg)
	if err != nil {
		return nil, nil, err
	}
	if written != len(msg) {
		return nil, nil, io.ErrShortWrite
	}
	buf := make([]byte, ip_mtu_trie.MTU)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, nil, err
	}
	var resp dnsmessage.Message
	if err = resp.Unpack(buf[:n]); err != nil {
		return nil, nil, err
	}
	return buf[:n], &resp, nil

}
