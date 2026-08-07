package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type temporaryPacketConn struct {
	*fakePacketConn
	reads atomic.Int64
}

func (c *temporaryPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	c.reads.Add(1)
	select {
	case <-c.closed:
		return 0, nil, net.ErrClosed
	default:
		return 0, nil, timeoutError{}
	}
}

type writeErrorPacketConn struct {
	*fakePacketConn
	err error
}

func (c *writeErrorPacketConn) WriteTo([]byte, net.Addr) (int, error) {
	return 0, c.err
}

type countingPacketConn struct {
	*fakePacketConn
	closeCalls atomic.Int32
}

type remotePacketConn struct {
	*fakePacketConn
	remote net.Addr
}

func (c *remotePacketConn) RemoteAddr() net.Addr { return c.remote }

type permanentListener struct {
	err   error
	calls atomic.Int32
}

func (l *permanentListener) Accept() (net.Conn, error) {
	l.calls.Add(1)
	return nil, l.err
}
func (l *permanentListener) Close() error   { return nil }
func (l *permanentListener) Addr() net.Addr { return testAddr("127.0.0.1:10006") }

type permanentReadPacketConn struct {
	*countingPacketConn
	err error
}

func (c *permanentReadPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, c.err
}

type readErrorConn struct {
	*scriptedConn
	err error
}

func (c *readErrorConn) Read([]byte) (int, error) { return 0, c.err }

type tcpAddrConn struct {
	net.Conn
	local  *net.TCPAddr
	remote *net.TCPAddr
}

func (c *tcpAddrConn) LocalAddr() net.Addr  { return c.local }
func (c *tcpAddrConn) RemoteAddr() net.Addr { return c.remote }

func (c *countingPacketConn) Close() error {
	c.closeCalls.Add(1)
	return c.fakePacketConn.Close()
}

func waitForResult[T any](t *testing.T, result <-chan T, name string) T {
	t.Helper()
	select {
	case value := <-result:
		return value
	case <-time.After(testTimeout):
		t.Fatalf("timed out waiting for %s", name)
		var zero T
		return zero
	}
}

func skipIfLocalNetworkDenied(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		t.Skipf("local network unavailable in test sandbox: %v", err)
	}
}

func TestServeUDPTemporaryErrorsDoNotSpin(t *testing.T) {
	p := newTestProxy(func(string, string) (net.Conn, error) {
		return nil, errors.New("unexpected dial")
	})
	pc := &temporaryPacketConn{fakePacketConn: newFakePacketConn("127.0.0.1:10001")}
	done := make(chan error, 1)
	go func() { done <- p.serveUDP(pc) }()
	t.Cleanup(func() {
		_ = p.Close()
		waitForResult(t, done, "UDP serve loop")
	})
	waitForSignal(t, p.UDPReady(), "UDP listener readiness")

	time.Sleep(40 * time.Millisecond)
	if calls := pc.reads.Load(); calls > 20 {
		t.Fatalf("ReadFrom called %d times in 40ms after temporary errors; loop is spinning", calls)
	}
}

func TestServeTCPPermanentErrorReturnsWithoutHandlingNil(t *testing.T) {
	acceptErr := errors.New("accept failed")
	listener := &permanentListener{err: acceptErr}
	var dialCalls atomic.Int32
	p := newTestProxy(func(string, string) (net.Conn, error) {
		dialCalls.Add(1)
		return nil, errors.New("unexpected dial")
	})
	t.Cleanup(func() { _ = p.Close() })
	err := p.serveTCP(listener)
	if !errors.Is(err, acceptErr) {
		t.Fatalf("serveTCP() error = %v, want %v", err, acceptErr)
	}
	if calls := listener.calls.Load(); calls != 1 {
		t.Fatalf("Accept calls = %d, want 1", calls)
	}
	if calls := dialCalls.Load(); calls != 0 {
		t.Fatalf("dial calls = %d, want 0", calls)
	}
}

func TestConcurrentCloseIsIdempotentAndWaitsForLoops(t *testing.T) {
	p := newTestProxy(func(string, string) (net.Conn, error) {
		return nil, errors.New("unexpected dial")
	})
	listener := newCloseListener()
	packetConn := newFakePacketConn("127.0.0.1:10007")
	tcpDone := make(chan error, 1)
	udpDone := make(chan error, 1)
	go func() { tcpDone <- p.serveTCP(listener) }()
	go func() { udpDone <- p.serveUDP(packetConn) }()
	waitForSignal(t, p.TCPReady(), "TCP readiness")
	waitForSignal(t, p.UDPReady(), "UDP readiness")

	const closers = 24
	results := make(chan error, closers)
	for range closers {
		go func() { results <- p.Close() }()
	}
	for range closers {
		if err := waitForResult(t, results, "concurrent Close"); err != nil {
			t.Fatal(err)
		}
	}
	if err := waitForResult(t, tcpDone, "TCP loop close"); err != nil {
		t.Fatal(err)
	}
	if err := waitForResult(t, udpDone, "UDP loop close"); err != nil {
		t.Fatal(err)
	}
}

func TestListenBindFailureReturnsErrorWithoutReady(t *testing.T) {
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		skipIfLocalNetworkDenied(t, err)
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tcp.Close() })
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		skipIfLocalNetworkDenied(t, err)
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udp.Close() })

	t.Run("TCP", func(t *testing.T) {
		p := newTestProxy(nil)
		t.Cleanup(func() { _ = p.Close() })
		if err := p.ListenTCP(tcp.Addr().String()); err == nil {
			t.Fatal("ListenTCP() error = nil on an occupied address")
		}
		select {
		case <-p.TCPReady():
			t.Fatal("TCP ready signaled after bind failure")
		default:
		}
	})

	t.Run("UDP", func(t *testing.T) {
		p := newTestProxy(nil)
		t.Cleanup(func() { _ = p.Close() })
		if err := p.ListenUDP(udp.LocalAddr().String()); err == nil {
			t.Fatal("ListenUDP() error = nil on an occupied address")
		}
		select {
		case <-p.UDPReady():
			t.Fatal("UDP ready signaled after bind failure")
		default:
		}
	})
}

func TestRealLoopbackTCPProxyLifecycle(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		skipIfLocalNetworkDenied(t, err)
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = upstream.Close() })
	upstreamDone := make(chan error, 1)
	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			upstreamDone <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(testTimeout))
		_, err = io.Copy(conn, conn)
		upstreamDone <- err
	}()

	p := newTestProxy(dialFunc(func(network, address string) (net.Conn, error) {
		return net.DialTimeout(network, address, testTimeout)
	}))
	p.AllocProjection(upstream.Addr().String())
	serveDone := make(chan error, 1)
	go func() { serveDone <- p.ListenTCP("127.0.0.1:0") }()
	t.Cleanup(func() {
		_ = p.Close()
	})
	waitForSignal(t, p.TCPReady(), "real TCP readiness")

	client, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(p.TCPPort())), testTimeout)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err := client.SetDeadline(time.Now().Add(testTimeout)); err != nil {
		t.Fatal(err)
	}
	payload := []byte("real loopback tcp payload")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("TCP payload = %q, want %q", got, payload)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if err := waitForResult(t, serveDone, "real TCP close"); err != nil {
		t.Fatalf("ListenTCP() after Close = %v", err)
	}
	_ = client.Close()
	_ = waitForResult(t, upstreamDone, "TCP echo shutdown")
}

func TestRealLoopbackTCPConcurrentConnections(t *testing.T) {
	const clients = 8
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		skipIfLocalNetworkDenied(t, err)
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = upstream.Close() })
	upstreamDone := make(chan error, clients)
	for range clients {
		go func() {
			conn, err := upstream.Accept()
			if err != nil {
				upstreamDone <- err
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(testTimeout))
			_, err = io.Copy(conn, conn)
			upstreamDone <- err
		}()
	}
	p := newTestProxy(dialFunc(func(network, address string) (net.Conn, error) {
		return net.DialTimeout(network, address, testTimeout)
	}))
	p.AllocProjection(upstream.Addr().String())
	serveDone := make(chan error, 1)
	go func() { serveDone <- p.ListenTCP("127.0.0.1:0") }()
	t.Cleanup(func() { _ = p.Close() })
	waitForSignal(t, p.TCPReady(), "concurrent TCP proxy readiness")

	results := make(chan error, clients)
	for i := range clients {
		go func() {
			conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(p.TCPPort())), testTimeout)
			if err != nil {
				results <- err
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(testTimeout))
			payload := []byte(fmt.Sprintf("concurrent payload %d", i))
			if _, err = conn.Write(payload); err == nil {
				got := make([]byte, len(payload))
				_, err = io.ReadFull(conn, got)
				if err == nil && !bytes.Equal(got, payload) {
					err = fmt.Errorf("payload = %q, want %q", got, payload)
				}
			}
			results <- err
		}()
	}
	for range clients {
		if err := waitForResult(t, results, "concurrent TCP client"); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if err := waitForResult(t, serveDone, "concurrent TCP proxy close"); err != nil {
		t.Fatal(err)
	}
	for range clients {
		_ = waitForResult(t, upstreamDone, "concurrent TCP upstream")
	}
}

func TestRelayTCPHalfCloseAndRemoteEarlyClose(t *testing.T) {
	localRelay, localClient := tcpConnPair(t)
	remoteRelay, remoteServer := tcpConnPair(t)
	for _, conn := range []*net.TCPConn{localRelay, localClient, remoteRelay, remoteServer} {
		conn := conn
		t.Cleanup(func() { _ = conn.Close() })
		_ = conn.SetDeadline(time.Now().Add(testTimeout))
	}
	done := make(chan error, 1)
	go func() { done <- RelayTCP(localRelay, remoteRelay) }()

	request := []byte("request before local half-close")
	if _, err := localClient.Write(request); err != nil {
		t.Fatal(err)
	}
	if err := localClient.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	gotRequest, err := io.ReadAll(remoteServer)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotRequest, request) {
		t.Fatalf("half-closed TCP request = %q, want %q", gotRequest, request)
	}

	response := []byte("response before remote early close")
	if _, err := remoteServer.Write(response); err != nil {
		t.Fatal(err)
	}
	if err := remoteServer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	gotResponse, err := io.ReadAll(localClient)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotResponse, response) {
		t.Fatalf("half-closed TCP response = %q, want %q", gotResponse, response)
	}
	if err := waitForResult(t, done, "TCP half-close relay"); err != nil {
		t.Fatalf("RelayTCP() error = %v", err)
	}
}

func tcpConnPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		skipIfLocalNetworkDenied(t, err)
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan *net.TCPConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptTCP()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()
	client, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case server := <-accepted:
		return server, client
	case err := <-acceptErr:
		_ = client.Close()
		t.Fatal(err)
	case <-time.After(testTimeout):
		_ = client.Close()
		t.Fatal("timed out accepting loopback TCP connection")
	}
	return nil, nil
}

func TestRelayTCPReturnsRealNetworkError(t *testing.T) {
	want := errors.New("real read failure")
	local := &readErrorConn{scriptedConn: newScriptedConn(nil), err: want}
	remote := newScriptedConn(nil)
	t.Cleanup(func() { _ = local.Close() })
	t.Cleanup(func() { _ = remote.Close() })
	if err := RelayTCP(local, remote); !errors.Is(err, want) {
		t.Fatalf("RelayTCP() error = %v, want %v", err, want)
	}
}

func TestHandleTCPDialFailureIsReturnedAndClientIsClosed(t *testing.T) {
	want := errors.New("TCP dial failed")
	p := newTestProxy(func(string, string) (net.Conn, error) { return nil, want })
	t.Cleanup(func() { _ = p.Close() })
	target := "127.0.0.1:41000"
	projection := p.AllocProjection(target)
	proxySide, clientSide := net.Pipe()
	t.Cleanup(func() { _ = proxySide.Close() })
	t.Cleanup(func() { _ = clientSide.Close() })
	conn := &tcpAddrConn{
		Conn:   proxySide,
		local:  &net.TCPAddr{IP: net.IP(projection.AsSlice()), Port: 10009},
		remote: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 30009},
	}
	if err := p.handleTCP(conn); !errors.Is(err, want) {
		t.Fatalf("handleTCP() error = %v, want %v", err, want)
	}
	_ = clientSide.SetReadDeadline(time.Now().Add(testTimeout))
	if _, err := clientSide.Read(make([]byte, 1)); err == nil {
		t.Fatal("client connection remained open after TCP dial failure")
	}
}

func TestCloseCancelsBlockedTCPHandlerDial(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	p := newTestProxy(contextDialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "127.0.0.1:41001" {
			return nil, fmt.Errorf("unexpected dial: %s %s", network, address)
		}
		close(started)
		<-ctx.Done()
		close(canceled)
		return nil, ctx.Err()
	}))
	t.Cleanup(func() { _ = p.Close() })
	projection := p.AllocProjection("127.0.0.1:41001")
	proxySide, clientSide := net.Pipe()
	t.Cleanup(func() { _ = proxySide.Close() })
	t.Cleanup(func() { _ = clientSide.Close() })
	conn := &tcpAddrConn{
		Conn:   proxySide,
		local:  &net.TCPAddr{IP: net.IP(projection.AsSlice()), Port: 10010},
		remote: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 30010},
	}
	p.startTCPHandler(conn)
	waitForSignal(t, started, "blocked TCP DialContext")

	closeDone := make(chan error, 1)
	go func() { closeDone <- p.Close() }()
	waitForSignal(t, canceled, "blocked TCP DialContext cancellation")
	if err := waitForResult(t, closeDone, "Proxy.Close with blocked TCP handler"); err != nil {
		t.Fatal(err)
	}
	if err := clientSide.SetReadDeadline(time.Now().Add(testTimeout)); err == nil {
		if _, err = clientSide.Read(make([]byte, 1)); err == nil {
			t.Fatal("TCP handler connection remained open after Close")
		}
	} else if !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}

func TestOutboundDialWithoutContextReturnsSentinelWithoutCallingDial(t *testing.T) {
	plain := &plainDialer{err: errors.New("plain Dial must not run")}
	p := newTestProxy(plain)
	t.Cleanup(func() { _ = p.Close() })

	t.Run("TCP", func(t *testing.T) {
		projection := p.AllocProjection("127.0.0.1:41002")
		proxySide, clientSide := net.Pipe()
		t.Cleanup(func() { _ = proxySide.Close() })
		t.Cleanup(func() { _ = clientSide.Close() })
		conn := &tcpAddrConn{
			Conn:   proxySide,
			local:  &net.TCPAddr{IP: net.IP(projection.AsSlice()), Port: 10011},
			remote: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 30011},
		}
		if err := p.handleTCP(conn); !errors.Is(err, ErrDialContextUnsupported) {
			t.Fatalf("handleTCP() error = %v, want %v", err, ErrDialContextUnsupported)
		}
	})

	t.Run("UDP", func(t *testing.T) {
		conn, err := p.GetOrBuildUDPConn(
			&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 30202},
			"127.0.0.1:40202",
			[]byte("unsupported context dialer"),
		)
		if conn != nil || !errors.Is(err, ErrDialContextUnsupported) {
			t.Fatalf("GetOrBuildUDPConn() = (%v, %v), want (nil, %v)", conn, err, ErrDialContextUnsupported)
		}
	})

	if got := plain.calls.Load(); got != 0 {
		t.Fatalf("plain Dial calls = %d, want 0", got)
	}
}

func TestRealLoopbackUDPProxyLifecycle(t *testing.T) {
	upstream, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		skipIfLocalNetworkDenied(t, err)
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = upstream.Close() })
	upstreamDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 65535)
		_ = upstream.SetReadDeadline(time.Now().Add(testTimeout))
		n, addr, err := upstream.ReadFromUDP(buf)
		if err == nil {
			_, err = upstream.WriteToUDP(buf[:n], addr)
		}
		upstreamDone <- err
	}()

	p := newTestProxy(dialFunc(func(network, address string) (net.Conn, error) {
		return net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	}))
	p.AllocProjection(upstream.LocalAddr().String())
	serveDone := make(chan error, 1)
	go func() { serveDone <- p.ListenUDP("127.0.0.1:0") }()
	t.Cleanup(func() {
		_ = p.Close()
	})
	waitForSignal(t, p.UDPReady(), "real UDP readiness")

	client, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: p.UDPPort()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	_ = client.SetDeadline(time.Now().Add(testTimeout))
	payload := []byte("real loopback udp payload")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload)+1)
	n, err := client.Read(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:n], payload) {
		t.Fatalf("UDP payload = %q, want %q", got[:n], payload)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if err := waitForResult(t, serveDone, "real UDP close"); err != nil {
		t.Fatalf("ListenUDP() after Close = %v", err)
	}
	if err := waitForResult(t, upstreamDone, "UDP echo"); err != nil {
		t.Fatalf("UDP echo = %v", err)
	}
}

func TestUDPConcurrentInitializationHasOneOwner(t *testing.T) {
	const callers = 16
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	upstream := &countingPacketConn{fakePacketConn: newFakePacketConn("127.0.0.1:20001")}
	p := newTestProxy(func(string, string) (net.Conn, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return upstream, nil
	})
	p.udpConn = newFakePacketConn("127.0.0.1:10001")
	t.Cleanup(func() { _ = p.Close() })
	client := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 30001}

	results := make(chan error, callers)
	var ready sync.WaitGroup
	ready.Add(callers)
	gate := make(chan struct{})
	for range callers {
		go func() {
			ready.Done()
			<-gate
			_, err := p.GetOrBuildUDPConn(client, "127.0.0.1:40001", []byte("not dns"))
			results <- err
		}()
	}
	ready.Wait()
	close(gate)
	waitForSignal(t, started, "UDP dial owner")
	close(release)
	for range callers {
		if err := waitForResult(t, results, "UDP initialization"); err != nil {
			t.Fatal(err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("UDP dial calls = %d, want 1", got)
	}
}

func TestCloseCancelsBlockedUDPDialOwner(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	var calls atomic.Int32
	p := newTestProxy(contextDialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		calls.Add(1)
		if network != "udp" || address != "127.0.0.1:40200" {
			return nil, fmt.Errorf("unexpected dial: %s %s", network, address)
		}
		close(started)
		<-ctx.Done()
		close(canceled)
		return nil, ctx.Err()
	}))
	t.Cleanup(func() { _ = p.Close() })

	type result struct {
		conn net.PacketConn
		err  error
	}
	getDone := make(chan result, 1)
	go func() {
		conn, err := p.GetOrBuildUDPConn(
			&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 30200},
			"127.0.0.1:40200",
			[]byte("blocked dial"),
		)
		getDone <- result{conn: conn, err: err}
	}()
	waitForSignal(t, started, "blocked UDP dial")

	closeDone := make(chan error, 1)
	go func() { closeDone <- p.Close() }()
	waitForSignal(t, p.closed, "Proxy.Close start")
	waitForSignal(t, canceled, "blocked UDP DialContext cancellation")
	if err := waitForResult(t, closeDone, "Proxy.Close after UDP dial cancellation"); err != nil {
		t.Fatalf("Proxy.Close() error = %v", err)
	}

	if conn, err := p.GetOrBuildUDPConn(
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 30201},
		"127.0.0.1:40201",
		[]byte("after close"),
	); conn != nil || !errors.Is(err, ErrProxyClosed) {
		t.Fatalf("GetOrBuildUDPConn() after Close start = (%v, %v), want (nil, %v)", conn, err, ErrProxyClosed)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("UDP dial calls after Close start = %d, want 1", got)
	}

	got := waitForResult(t, getDone, "blocked UDP owner shutdown")
	if got.conn != nil || !errors.Is(got.err, ErrProxyClosed) {
		t.Fatalf("blocked GetOrBuildUDPConn() = (%v, %v), want (nil, %v)", got.conn, got.err, ErrProxyClosed)
	}
}

func TestUDPConnMappingRemoveIsLockedAndOwnerChecked(t *testing.T) {
	t.Run("Remove waits for mutex", func(t *testing.T) {
		mapping := NewUDPConnMapping()
		upstream := newFakePacketConn("127.0.0.1:20202")
		t.Cleanup(func() { _ = upstream.Close() })

		mapping.Lock()
		mapping.Insert("client", upstream)
		started := make(chan struct{})
		removed := make(chan struct{})
		go func() {
			close(started)
			mapping.Remove("client")
			close(removed)
		}()
		select {
		case <-started:
		case <-time.After(testTimeout):
			mapping.Unlock()
			t.Fatal("timed out starting UDP mapping Remove")
		}
		returnedWhileLocked := false
		select {
		case <-removed:
			returnedWhileLocked = true
		case <-time.After(50 * time.Millisecond):
		}
		mapping.Unlock()
		if returnedWhileLocked {
			t.Fatal("UDPConnMapping.Remove returned while the mapping mutex was held")
		}
		waitForSignal(t, removed, "locked UDP mapping Remove")
		waitForSignal(t, upstream.closed, "removed UDP connection close")
	})

	t.Run("RemoveIf keeps a replacement owner", func(t *testing.T) {
		mapping := NewUDPConnMapping()
		mapping.Lock()
		oldOwner := mapping.Insert("client", nil)
		replacement := mapping.Insert("client", nil)
		mapping.Unlock()

		mapping.RemoveIf("client", oldOwner)
		mapping.Lock()
		got, ok := mapping.Get("client")
		mapping.Unlock()
		if !ok || got != replacement {
			t.Fatalf("mapping after stale RemoveIf = (%v, %v), want replacement owner", got, ok)
		}

		mapping.RemoveIf("client", replacement)
		mapping.Lock()
		_, ok = mapping.Get("client")
		mapping.Unlock()
		if ok {
			t.Fatal("mapping remains after owner-matched RemoveIf")
		}
	})
}

func TestSlowUDPSessionDoesNotBlockAnotherClient(t *testing.T) {
	slowStarted := make(chan struct{})
	releaseSlow := make(chan struct{})
	p := newTestProxy(func(_ string, target string) (net.Conn, error) {
		if target == "127.0.0.1:40101" {
			close(slowStarted)
			<-releaseSlow
		}
		return newFakePacketConn("127.0.0.1:20101"), nil
	})
	p.udpConn = newFakePacketConn("127.0.0.1:10101")
	t.Cleanup(func() {
		select {
		case <-releaseSlow:
		default:
			close(releaseSlow)
		}
		_ = p.Close()
	})
	slowDone := make(chan error, 1)
	go func() {
		_, err := p.GetOrBuildUDPConn(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 30101}, "127.0.0.1:40101", []byte("slow"))
		slowDone <- err
	}()
	waitForSignal(t, slowStarted, "slow UDP dial")

	fastDone := make(chan error, 1)
	go func() {
		_, err := p.GetOrBuildUDPConn(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 30102}, "127.0.0.1:40102", []byte("fast"))
		fastDone <- err
	}()
	if err := waitForResult(t, fastDone, "independent UDP session"); err != nil {
		t.Fatal(err)
	}
	close(releaseSlow)
	if err := waitForResult(t, slowDone, "slow UDP session"); err != nil {
		t.Fatal(err)
	}
}

func TestUDPInitializationFailureWakesWaitersAndRemovesSession(t *testing.T) {
	const callers = 12
	dialErr := errors.New("UDP dial failed")
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	p := newTestProxy(func(string, string) (net.Conn, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return nil, dialErr
	})
	t.Cleanup(func() { _ = p.Close() })
	client := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 30002}
	results := make(chan error, callers)
	gate := make(chan struct{})
	for range callers {
		go func() {
			<-gate
			_, err := p.GetOrBuildUDPConn(client, "127.0.0.1:40002", []byte("not dns"))
			results <- err
		}()
	}
	close(gate)
	waitForSignal(t, started, "failed UDP dial owner")
	deadline := time.Now().Add(testTimeout)
	for {
		p.nm.Lock()
		conn, ok := p.nm.Get(client.String())
		waiters := 0
		if ok {
			waiters = conn.waiters
		}
		p.nm.Unlock()
		if waiters == callers-1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("UDP initialization waiters = %d, want %d", waiters, callers-1)
		}
		runtime.Gosched()
	}
	close(release)
	for range callers {
		if err := waitForResult(t, results, "failed UDP initialization"); !errors.Is(err, dialErr) {
			t.Fatalf("GetOrBuildUDPConn() error = %v, want %v", err, dialErr)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("UDP dial calls after one failed concurrent initialization = %d, want 1", got)
	}
	p.nm.Lock()
	_, ok := p.nm.Get(client.String())
	p.nm.Unlock()
	if ok {
		t.Fatal("failed UDP session remains in mapping")
	}
}

func TestUDPWriteFailureClosesConnAndRemovesMapping(t *testing.T) {
	writeErr := errors.New("upstream write failed")
	upstream := &countingPacketConn{fakePacketConn: newFakePacketConn("127.0.0.1:20003")}
	failing := &writeErrorPacketConn{fakePacketConn: upstream.fakePacketConn, err: writeErr}
	p := newTestProxy(func(string, string) (net.Conn, error) { return failing, nil })
	p.udpConn = newFakePacketConn("127.0.0.1:10003")
	t.Cleanup(func() { _ = p.Close() })
	target := "127.0.0.1:40003"
	p.AllocProjection(target)
	client := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 30003}

	err := p.handleUDP(client, []byte("not dns"))
	if !errors.Is(err, writeErr) {
		t.Fatalf("handleUDP() error = %v, want %v", err, writeErr)
	}
	select {
	case <-failing.closed:
	case <-time.After(testTimeout):
		t.Fatal("UDP PacketConn was not closed after WriteTo failure")
	}
	p.nm.Lock()
	_, ok := p.nm.Get(client.String())
	p.nm.Unlock()
	if ok {
		t.Fatal("UDP mapping remains after WriteTo failure")
	}
}

func TestUDPReadFailureAndIdleTimeoutCleanUpSession(t *testing.T) {
	for _, tc := range []struct {
		name     string
		upstream func() (*countingPacketConn, net.Conn)
	}{
		{name: "read failure", upstream: func() (*countingPacketConn, net.Conn) {
			base := &countingPacketConn{fakePacketConn: newFakePacketConn("127.0.0.1:20008")}
			return base, &permanentReadPacketConn{countingPacketConn: base, err: errors.New("upstream read failed")}
		}},
		{name: "idle timeout", upstream: func() (*countingPacketConn, net.Conn) {
			base := &countingPacketConn{fakePacketConn: newFakePacketConn("127.0.0.1:20009")}
			return base, base
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base, upstream := tc.upstream()
			p := newTestProxy(func(string, string) (net.Conn, error) { return upstream, nil })
			p.udpConn = newFakePacketConn("127.0.0.1:10008")
			p.udpTTL = func([]byte) time.Duration { return 25 * time.Millisecond }
			t.Cleanup(func() { _ = p.Close() })
			client := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 30008}
			if _, err := p.GetOrBuildUDPConn(client, "127.0.0.1:40008", []byte("not dns")); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(testTimeout)
			for {
				p.nm.Lock()
				_, ok := p.nm.Get(client.String())
				p.nm.Unlock()
				if !ok {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("UDP mapping was not removed after relay exit")
				}
				runtime.Gosched()
			}
			for base.closeCalls.Load() != 1 {
				if time.Now().After(deadline) {
					t.Fatalf("UDP PacketConn close calls = %d, want 1", base.closeCalls.Load())
				}
				runtime.Gosched()
			}
		})
	}
}

func TestRelayUDPMaximumDatagramUsesExactLength(t *testing.T) {
	target := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40010}
	upstream := &remotePacketConn{fakePacketConn: newFakePacketConn("127.0.0.1:20010"), remote: target}
	proxySocket := newFakePacketConn("127.0.0.1:10010")
	p := newTestProxy(nil)
	p.udpConn = proxySocket
	t.Cleanup(func() {
		_ = upstream.Close()
		_ = p.Close()
	})
	payload := bytes.Repeat([]byte{0xa5}, 65535)
	done := make(chan error, 1)
	go func() {
		done <- p.relayUDP(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 30010}, upstream, testTimeout)
	}()
	upstream.reads <- packet{data: payload, addr: target}
	got := waitForPacket(t, proxySocket.writes, "maximum UDP datagram")
	if len(got.data) != len(payload) || !bytes.Equal(got.data, payload) {
		t.Fatalf("relayed UDP datagram length = %d, want %d", len(got.data), len(payload))
	}
	_ = upstream.Close()
	_ = waitForResult(t, done, "maximum UDP relay shutdown")
}

func TestRelayUDPIgnoresUnexpectedSourceAndUsesExactPayload(t *testing.T) {
	target := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40004}
	upstream := &remotePacketConn{fakePacketConn: newFakePacketConn("127.0.0.1:20004"), remote: target}
	proxySocket := newFakePacketConn("127.0.0.1:10004")
	p := newTestProxy(nil)
	p.udpConn = proxySocket
	t.Cleanup(func() {
		_ = upstream.Close()
		_ = p.Close()
	})
	client := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 30004}
	done := make(chan error, 1)
	go func() { done <- p.relayUDP(client, upstream, 200*time.Millisecond) }()
	upstream.reads <- packet{data: []byte("spoofed"), addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 49999}}
	upstream.reads <- packet{data: []byte("valid"), addr: target}

	got := waitForPacket(t, proxySocket.writes, "validated UDP response")
	if string(got.data) != "valid" {
		t.Fatalf("relayed UDP payload = %q, want valid", got.data)
	}
	_ = upstream.Close()
	_ = waitForResult(t, done, "UDP relay shutdown")
}

func TestCloseClosesUDPSessionsAndWaitsForRelay(t *testing.T) {
	upstream := &countingPacketConn{fakePacketConn: newFakePacketConn("127.0.0.1:20005")}
	p := newTestProxy(func(string, string) (net.Conn, error) { return upstream, nil })
	p.udpConn = newFakePacketConn("127.0.0.1:10005")
	client := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 30005}
	if _, err := p.GetOrBuildUDPConn(client, "127.0.0.1:40005", []byte("not dns")); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if calls := upstream.closeCalls.Load(); calls != 1 {
		t.Fatalf("UDP session close calls = %d, want 1", calls)
	}
	p.nm.Lock()
	count := len(p.nm.nm)
	p.nm.Unlock()
	if count != 0 {
		t.Fatalf("UDP mappings after Close = %d, want 0", count)
	}
}

func TestForwardDNSMessageSupportsResponseLargerThan512Bytes(t *testing.T) {
	name := dnsmessage.MustNewName("large.example.test.")
	response := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 77, Response: true},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}},
	}
	for i := range 12 {
		response.Answers = append(response.Answers, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: uint32(i)},
			Body:   &dnsmessage.TXTResource{TXT: []string{string(bytes.Repeat([]byte{'x'}, 80))}},
		})
	}
	responseBytes, err := response.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if len(responseBytes) <= 512 {
		t.Fatalf("test DNS response length = %d, want > 512", len(responseBytes))
	}
	conn := newScriptedConn(responseBytes)
	got, parsed, err := forwardDNSMessageWithDial("127.0.0.1:53", []byte{0, 1}, testTimeout, func(string, string, time.Duration) (net.Conn, error) {
		return conn, nil
	})
	if err != nil {
		t.Fatalf("forwardDNSMessageWithDial() error = %v", err)
	}
	if !bytes.Equal(got, responseBytes) {
		t.Fatalf("DNS response length = %d, want %d", len(got), len(responseBytes))
	}
	if len(parsed.Answers) != len(response.Answers) {
		t.Fatalf("DNS answers = %d, want %d", len(parsed.Answers), len(response.Answers))
	}
}

func TestForwardDNSMessageRejectsEmptyAndMalformedResponses(t *testing.T) {
	for name, response := range map[string][]byte{
		"empty":     nil,
		"malformed": {0xde, 0xad, 0xbe, 0xef},
	} {
		t.Run(name, func(t *testing.T) {
			conn := newScriptedConn(response)
			got, parsed, err := forwardDNSMessageWithDial("127.0.0.1:53", []byte{0, 1}, 50*time.Millisecond, func(string, string, time.Duration) (net.Conn, error) {
				return conn, nil
			})
			if err == nil || got != nil || parsed != nil {
				t.Fatalf("forwardDNSMessageWithDial() = (%x, %v, %v), want nil, nil, error", got, parsed, err)
			}
			if !conn.closed.Load() {
				t.Fatal("DNS connection was not closed after invalid response")
			}
		})
	}
}

func TestForwardDNSMessageNoResponseHonorsInjectedDeadline(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	t.Cleanup(func() { _ = server.Close() })
	timeout := 30 * time.Millisecond
	started := time.Now()
	_, _, err := forwardDNSMessageWithDial("127.0.0.1:53", []byte{0, 1}, timeout, func(string, string, time.Duration) (net.Conn, error) {
		return client, nil
	})
	if err == nil {
		t.Fatal("forwardDNSMessageWithDial() error = nil for non-responsive upstream")
	}
	if elapsed := time.Since(started); elapsed > testTimeout {
		t.Fatalf("DNS timeout returned after %v, deadline %v", elapsed, timeout)
	}
}

func TestProxyCloseInterruptsInFlightDNSForward(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	t.Cleanup(func() { _ = server.Close() })
	dialed := make(chan struct{})
	p := newTestProxy(nil)
	p.dnsDial = func(context.Context, string, string) (net.Conn, error) {
		close(dialed)
		return client, nil
	}
	p.udpConn = newFakePacketConn("127.0.0.1:10011")
	p.AllocProjection("127.0.0.1:53")
	name := dnsmessage.MustNewName("close.example.test.")
	message := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 91, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
	query, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	p.startUDPHandler(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 30011}, query)
	waitForSignal(t, dialed, "DNS forward dial")
	done := make(chan error, 1)
	go func() { done <- p.Close() }()
	if err := waitForResult(t, done, "Close with in-flight DNS forward"); err != nil {
		t.Fatal(err)
	}
	if err := server.SetReadDeadline(time.Now().Add(testTimeout)); err == nil {
		if _, err = server.Read(make([]byte, 1)); err == nil {
			t.Fatal("tracked DNS connection remained open after Close")
		}
	} else if !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}

func TestProxyCloseCancelsDNSDialBeforeConnectionReturns(t *testing.T) {
	dialStarted := make(chan time.Time, 1)
	dialCanceled := make(chan struct{})
	p := newTestProxy(nil)
	p.dnsDial = func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "udp" || address != "127.0.0.1:53" {
			return nil, fmt.Errorf("unexpected DNS dial: %s %s", network, address)
		}
		deadline, _ := ctx.Deadline()
		dialStarted <- deadline
		<-ctx.Done()
		close(dialCanceled)
		return nil, ctx.Err()
	}
	p.udpConn = newFakePacketConn("127.0.0.1:10012")
	t.Cleanup(func() { _ = p.Close() })
	p.AllocProjection("127.0.0.1:53")
	name := dnsmessage.MustNewName("dial-close.example.test.")
	message := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 92, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
	query, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	p.startUDPHandler(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 30012}, query)
	deadline := waitForResult(t, dialStarted, "context-bound DNS dial")
	if deadline.IsZero() {
		t.Fatal("DNS dial context has no per-call deadline")
	}
	remaining := time.Until(deadline)
	if remaining <= 0 || remaining > DnsQueryTimeout {
		t.Fatalf("DNS dial deadline remaining = %v, want within (0, %v]", remaining, DnsQueryTimeout)
	}

	done := make(chan error, 1)
	go func() { done <- p.Close() }()
	waitForSignal(t, dialCanceled, "DNS dial cancellation")
	if err := waitForResult(t, done, "Close with DNS dial before connection return"); err != nil {
		t.Fatal(err)
	}
}

func TestMapperPreservesIPv4AndIPv6Targets(t *testing.T) {
	p := newTestProxy(nil)
	for _, target := range []string{"10.0.0.1:443", "[fd00::1]:443", "example.test"} {
		projection := p.AllocProjection(target)
		if got := p.GetProjection(projection); got != target {
			t.Fatalf("GetProjection(AllocProjection(%q)) = %q", target, got)
		}
	}
	v4Projection := p.AllocProjection("192.168.1.1:80")
	mapped := netip.AddrFrom16(v4Projection.As16())
	if got := p.GetProjection(mapped); got != "192.168.1.1:80" {
		t.Fatalf("IPv4-mapped projection lookup = %q", got)
	}
	checks := []struct {
		ip       string
		loopback bool
		private  bool
	}{
		{"127.0.0.1", true, false},
		{"::1", true, false},
		{"10.0.0.1", false, true},
		{"fd00::1", false, true},
		{"8.8.8.8", false, false},
		{"2001:4860:4860::8888", false, false},
	}
	for _, check := range checks {
		ip := netip.MustParseAddr(check.ip)
		if ip.IsLoopback() != check.loopback || ip.IsPrivate() != check.private {
			t.Fatalf("address classification for %s = loopback:%v private:%v", ip, ip.IsLoopback(), ip.IsPrivate())
		}
	}
}
