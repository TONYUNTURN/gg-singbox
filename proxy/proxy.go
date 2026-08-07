package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	ggdialer "github.com/mzz2017/gg/dialer"
	"github.com/mzz2017/gg/infra/ip_mtu_trie"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/proxy"
)

var (
	ErrProxyClosed            = errors.New("proxy closed")
	ErrDialContextUnsupported = errors.New("proxy dialer does not support context-aware dialing")
)

type Proxy struct {
	mutex        sync.Mutex      // mutex protects the mappers
	addrMapper   *LoopbackMapper // addrMapper projects an address to a loopback IP
	domainMapper *ReservedMapper // domainMapper projects a domain to a reserved IP
	realIPMapper *RealIPMapper   // realIPMapper projects a fake IP to a real IP

	log    *logrus.Logger
	dialer proxy.Dialer
	udpTTL func([]byte) time.Duration

	ctx     context.Context
	cancel  context.CancelFunc
	dnsDial func(context.Context, string, string) (net.Conn, error)
	closed  chan struct{}
	closeMu sync.Once

	lifecycleMu sync.Mutex
	listener    net.Listener
	udpConn     net.PacketConn
	tcpServing  bool
	udpServing  bool
	closing     bool
	closeErr    error
	connections map[net.Conn]struct{}
	wg          sync.WaitGroup

	tcpListened chan struct{}
	udpListened chan struct{}
	tcpReady    sync.Once
	udpReady    sync.Once

	nm *UDPConnMapping
}

func New(logger *logrus.Logger, dialer proxy.Dialer) *Proxy {
	ctx, cancel := context.WithCancel(context.Background())
	netDialer := &net.Dialer{}
	return &Proxy{
		addrMapper:   NewLoopbackMapper(),
		domainMapper: NewReservedMapper(),
		realIPMapper: NewRealIPMapper(),
		log:          logger,
		dialer:       dialer,
		udpTTL:       selectTimeout,
		ctx:          ctx,
		cancel:       cancel,
		dnsDial:      netDialer.DialContext,
		closed:       make(chan struct{}),
		connections:  make(map[net.Conn]struct{}),
		tcpListened:  make(chan struct{}),
		udpListened:  make(chan struct{}),
		nm:           NewUDPConnMapping(),
	}
}

func (p *Proxy) AllocProjection(target string) (loopback netip.Addr) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if strings.Contains(target, ":") {
		// address
		return p.addrMapper.Alloc(target)
	} else {
		// domain
		return p.domainMapper.Alloc(target)
	}
}

func (p *Proxy) GetProjection(ip netip.Addr) (target string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if ip.Is4In6() {
		ip = netip.AddrFrom4(ip.As4())
	}
	if ip.IsLoopback() {
		// loopback IP -> target address
		return p.addrMapper.Get(ip)
	} else {
		// reserved IP -> domain
		return p.domainMapper.Get(ip)
	}
}

func (p *Proxy) GetRealIP(fakeIP netip.Addr) (realIP netip.Addr, ok bool) {
	return p.realIPMapper.Get(fakeIP)
}

// ListenAndServe will block the goroutine.
func (p *Proxy) ListenAndServe(port int) error {
	addr := net.JoinHostPort("0.0.0.0", strconv.Itoa(port))
	eCh := make(chan error, 2)
	go func() {
		e := p.ListenTCP(addr)
		eCh <- e
	}()
	select {
	case e := <-eCh:
		return e
	case <-p.tcpListened:
		// listen udp
		addr = net.JoinHostPort("0.0.0.0", strconv.Itoa(p.TCPPort()))
		go func() {
			e := p.ListenUDP(addr)
			eCh <- e
		}()
	}
	defer p.Close()
	return <-eCh
}

func (p *Proxy) ListenTCP(addr string) (err error) {
	lt, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return p.serveTCP(lt)
}

// serveTCP runs the TCP accept loop on an already-created listener. Keeping
// listener creation separate makes listener lifecycle tests deterministic.
func (p *Proxy) serveTCP(lt net.Listener) error {
	if err := p.startTCP(lt); err != nil {
		_ = lt.Close()
		if errors.Is(err, ErrProxyClosed) {
			return nil
		}
		return err
	}
	defer p.finishTCP(lt)
	retry := 0
	for {
		conn, err := lt.Accept()
		if err != nil {
			if conn != nil {
				_ = conn.Close()
			}
			if errors.Is(err, net.ErrClosed) || p.isClosing() {
				return nil
			}
			if p.waitTemporaryError(err, retry) {
				retry++
				continue
			}
			return fmt.Errorf("accept TCP connection: %w", err)
		}
		retry = 0
		if conn == nil {
			return errors.New("accept TCP connection: nil connection")
		}
		p.startTCPHandler(conn)
	}
}

func (p *Proxy) ListenUDP(addr string) (err error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	lu, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	return p.serveUDP(lu)
}

// serveUDP runs the UDP receive loop on an already-created packet socket.
func (p *Proxy) serveUDP(lu net.PacketConn) error {
	if err := p.startUDP(lu); err != nil {
		_ = lu.Close()
		if errors.Is(err, ErrProxyClosed) {
			return nil
		}
		return err
	}
	defer p.finishUDP(lu)
	var buf [ip_mtu_trie.MTU]byte
	retry := 0
	for {
		n, lAddr, err := lu.ReadFrom(buf[:])
		if err != nil {
			if errors.Is(err, net.ErrClosed) || p.isClosing() {
				return nil
			}
			if p.waitTemporaryError(err, retry) {
				retry++
				continue
			}
			return fmt.Errorf("read UDP packet: %w", err)
		}
		retry = 0
		if lAddr == nil || n < 0 || n > len(buf) {
			return fmt.Errorf("read UDP packet: invalid result n=%d addr=%v", n, lAddr)
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		p.startUDPHandler(lAddr, data)
	}
}

func (p *Proxy) TCPPort() int {
	p.lifecycleMu.Lock()
	defer p.lifecycleMu.Unlock()
	if p.listener == nil {
		return 0
	}
	_, port, err := net.SplitHostPort(p.listener.Addr().String())
	if err != nil {
		return 0
	}
	parsed, _ := strconv.Atoi(port)
	return parsed
}

func (p *Proxy) UDPPort() int {
	p.lifecycleMu.Lock()
	defer p.lifecycleMu.Unlock()
	if p.udpConn == nil {
		return 0
	}
	_, port, err := net.SplitHostPort(p.udpConn.LocalAddr().String())
	if err != nil {
		return 0
	}
	parsed, err := strconv.Atoi(port)
	if err != nil {
		return 0
	}
	return parsed
}

func (p *Proxy) TCPReady() <-chan struct{} {
	return p.tcpListened
}

func (p *Proxy) UDPReady() <-chan struct{} {
	return p.udpListened
}

func (p *Proxy) Close() error {
	p.closeMu.Do(func() {
		p.lifecycleMu.Lock()
		p.closing = true
		p.cancel()
		close(p.closed)
		listener := p.listener
		udpConn := p.udpConn
		connections := make([]net.Conn, 0, len(p.connections))
		for conn := range p.connections {
			connections = append(connections, conn)
		}
		p.lifecycleMu.Unlock()

		p.recordCloseError(closeNetworkResource(listener))
		p.recordCloseError(closeNetworkResource(udpConn))
		for _, conn := range connections {
			p.recordCloseError(closeNetworkResource(conn))
		}
		p.nm.CloseAll(ErrProxyClosed)
		p.wg.Wait()
	})
	return p.closeErr
}

func (p *Proxy) startTCP(listener net.Listener) error {
	p.lifecycleMu.Lock()
	defer p.lifecycleMu.Unlock()
	if p.closing {
		return ErrProxyClosed
	}
	if p.tcpServing {
		return errors.New("TCP listener already started")
	}
	p.tcpServing = true
	p.listener = listener
	p.wg.Add(1)
	p.tcpReady.Do(func() { close(p.tcpListened) })
	return nil
}

func (p *Proxy) finishTCP(listener net.Listener) {
	_ = listener.Close()
	p.lifecycleMu.Lock()
	if p.listener == listener {
		p.listener = nil
	}
	p.tcpServing = false
	p.lifecycleMu.Unlock()
	p.wg.Done()
}

func (p *Proxy) startUDP(conn net.PacketConn) error {
	p.lifecycleMu.Lock()
	defer p.lifecycleMu.Unlock()
	if p.closing {
		return ErrProxyClosed
	}
	if p.udpServing {
		return errors.New("UDP listener already started")
	}
	p.udpServing = true
	p.udpConn = conn
	p.wg.Add(1)
	p.udpReady.Do(func() { close(p.udpListened) })
	return nil
}

func (p *Proxy) finishUDP(conn net.PacketConn) {
	_ = conn.Close()
	p.lifecycleMu.Lock()
	if p.udpConn == conn {
		p.udpConn = nil
	}
	p.udpServing = false
	p.lifecycleMu.Unlock()
	p.wg.Done()
}

func (p *Proxy) startTCPHandler(conn net.Conn) {
	if !p.trackConn(conn) {
		_ = conn.Close()
		return
	}
	go func() {
		defer p.untrackConn(conn)
		if err := p.handleTCP(conn); err != nil && !errors.Is(err, ErrProxyClosed) {
			p.log.Warnf("handleTCP: %v", err)
		}
	}()
}

func (p *Proxy) startUDPHandler(addr net.Addr, data []byte) {
	p.lifecycleMu.Lock()
	if p.closing {
		p.lifecycleMu.Unlock()
		return
	}
	p.wg.Add(1)
	p.lifecycleMu.Unlock()
	go func() {
		defer p.wg.Done()
		if err := p.handleUDP(addr, data); err != nil && !errors.Is(err, ErrProxyClosed) {
			p.log.Infof("handleUDP: %v", err)
		}
	}()
}

func (p *Proxy) trackConn(conn net.Conn) bool {
	p.lifecycleMu.Lock()
	defer p.lifecycleMu.Unlock()
	if p.closing {
		return false
	}
	p.connections[conn] = struct{}{}
	p.wg.Add(1)
	return true
}

func (p *Proxy) untrackConn(conn net.Conn) {
	p.lifecycleMu.Lock()
	delete(p.connections, conn)
	p.lifecycleMu.Unlock()
	p.wg.Done()
}

type contextDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

// dialContext only uses a dialer that natively exposes cancellation. The
// production dialer wrapper embeds its implementation, so unwrap that narrow
// layer before checking for DialContext support.
func (p *Proxy) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, p.contextDialError(err)
	}
	dialer := p.dialer
	for {
		wrapped, ok := dialer.(*ggdialer.Dialer)
		if !ok || wrapped == nil {
			break
		}
		dialer = wrapped.Dialer
	}
	dialerWithContext, ok := dialer.(contextDialer)
	if !ok {
		return nil, fmt.Errorf("%w: %T", ErrDialContextUnsupported, dialer)
	}
	conn, err := dialerWithContext.DialContext(ctx, network, address)
	if err != nil {
		return nil, p.contextDialError(err)
	}
	if conn == nil {
		return nil, errors.New("context-aware dialer returned a nil connection")
	}
	return conn, nil
}

func (p *Proxy) contextDialError(err error) error {
	if errors.Is(p.ctx.Err(), context.Canceled) {
		return ErrProxyClosed
	}
	return err
}

type trackedConn struct {
	net.Conn
	proxy *Proxy
	once  sync.Once
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.proxy.untrackConn(c) })
	return err
}

func (p *Proxy) dialTracked(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := p.dnsDial(ctx, network, address)
	if err != nil {
		return nil, p.contextDialError(err)
	}
	if conn == nil {
		return nil, errors.New("DNS dial returned a nil connection")
	}
	tracked := &trackedConn{Conn: conn, proxy: p}
	if !p.trackConn(tracked) {
		_ = conn.Close()
		return nil, ErrProxyClosed
	}
	return tracked, nil
}

func (p *Proxy) isClosing() bool {
	p.lifecycleMu.Lock()
	defer p.lifecycleMu.Unlock()
	return p.closing
}

func (p *Proxy) packetConn() net.PacketConn {
	p.lifecycleMu.Lock()
	defer p.lifecycleMu.Unlock()
	return p.udpConn
}

func (p *Proxy) waitTemporaryError(err error, retry int) bool {
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Temporary() {
		return false
	}
	delay := 5 * time.Millisecond
	for i := 0; i < retry && delay < 250*time.Millisecond; i++ {
		delay *= 2
	}
	if delay > 250*time.Millisecond {
		delay = 250 * time.Millisecond
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-p.closed:
		return true
	}
}

func closeNetworkResource(closer ioCloser) error {
	if closer == nil {
		return nil
	}
	if err := closer.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

type ioCloser interface {
	Close() error
}

func (p *Proxy) recordCloseError(err error) {
	if err != nil && p.closeErr == nil {
		p.closeErr = err
	}
}
