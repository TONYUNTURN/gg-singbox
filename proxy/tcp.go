package proxy

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
)

func (p *Proxy) handleTCP(conn net.Conn) error {
	defer conn.Close()
	loopback, _ := netip.AddrFromSlice(conn.LocalAddr().(*net.TCPAddr).IP)
	tgt := p.GetProjection(loopback)
	if tgt == "" {
		return fmt.Errorf("mapped target address not found: %v", loopback)
	}
	p.log.Tracef("received tcp: %v, tgt: %v", conn.RemoteAddr().String(), tgt)
	c, err := p.dialer.Dial("tcp", tgt)
	if err != nil {
		return err
	}
	defer c.Close()
	if err = RelayTCP(conn, c); err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return nil // ignore i/o timeout
		}
		return fmt.Errorf("handleTCP relay error: %w", err)
	}
	return nil
}


type WriteCloser interface {
	CloseWrite() error
}

func RelayTCP(lConn, rConn net.Conn) (err error) {
	// 256KB buffer for high-latency proxy connections
	buf := make([]byte, 256*1024)
	eCh := make(chan error, 1)
	go func() {
		_, e := io.CopyBuffer(rConn, lConn, buf)
		if rConn, ok := rConn.(WriteCloser); ok {
			rConn.CloseWrite()
		}
		eCh <- e
	}()
	_, e := io.CopyBuffer(lConn, rConn, buf)
	if lConn, ok := lConn.(WriteCloser); ok {
		lConn.CloseWrite()
	}
	if e != nil {
		<-eCh
		return e
	}
	return <-eCh
}