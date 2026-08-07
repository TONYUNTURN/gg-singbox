package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ggdialer "github.com/mzz2017/gg/dialer"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/dns/dnsmessage"
)

const testTimeout = 2 * time.Second

type dialFunc func(network, address string) (net.Conn, error)

func (f dialFunc) Dial(network, address string) (net.Conn, error) {
	return f(network, address)
}

func (f dialFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return f(network, address)
}

type contextDialFunc func(context.Context, string, string) (net.Conn, error)

func (f contextDialFunc) Dial(network, address string) (net.Conn, error) {
	return f(context.Background(), network, address)
}

func (f contextDialFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

type plainDialer struct {
	calls atomic.Int32
	err   error
}

func (d *plainDialer) Dial(string, string) (net.Conn, error) {
	d.calls.Add(1)
	return nil, d.err
}

type preferredContextDialer struct {
	dialCalls        atomic.Int32
	dialContextCalls atomic.Int32
	conn             net.Conn
}

func (d *preferredContextDialer) Dial(string, string) (net.Conn, error) {
	d.dialCalls.Add(1)
	return nil, errors.New("plain Dial must not be called")
}

func (d *preferredContextDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	d.dialContextCalls.Add(1)
	return d.conn, nil
}

type closeListener struct {
	closed chan struct{}
	once   sync.Once
}

func newCloseListener() *closeListener {
	return &closeListener{closed: make(chan struct{})}
}

func (l *closeListener) Accept() (net.Conn, error) {
	<-l.closed
	return nil, net.ErrClosed
}

func (l *closeListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *closeListener) Addr() net.Addr { return testAddr("127.0.0.1:0") }

type testAddr string

func (a testAddr) Network() string { return "test" }
func (a testAddr) String() string  { return string(a) }

type scriptedConn struct {
	reader      *bytes.Reader
	written     bytes.Buffer
	deadline    time.Time
	closed      atomic.Bool
	writeClosed atomic.Bool
}

func newScriptedConn(read []byte) *scriptedConn {
	return &scriptedConn{reader: bytes.NewReader(read)}
}

func (c *scriptedConn) Read(b []byte) (int, error)         { return c.reader.Read(b) }
func (c *scriptedConn) Write(b []byte) (int, error)        { return c.written.Write(b) }
func (c *scriptedConn) Close() error                       { c.closed.Store(true); return nil }
func (c *scriptedConn) CloseWrite() error                  { c.writeClosed.Store(true); return nil }
func (c *scriptedConn) LocalAddr() net.Addr                { return testAddr("127.0.0.1:1") }
func (c *scriptedConn) RemoteAddr() net.Addr               { return testAddr("127.0.0.1:2") }
func (c *scriptedConn) SetDeadline(t time.Time) error      { c.deadline = t; return nil }
func (c *scriptedConn) SetReadDeadline(t time.Time) error  { c.deadline = t; return nil }
func (c *scriptedConn) SetWriteDeadline(t time.Time) error { c.deadline = t; return nil }

type packet struct {
	data []byte
	addr net.Addr
}

type fakePacketConn struct {
	local         net.Addr
	reads         chan packet
	writes        chan packet
	closed        chan struct{}
	closeOnce     sync.Once
	deadlineMutex sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time
	onWrite       func([]byte, net.Addr)
}

func newFakePacketConn(local string) *fakePacketConn {
	return &fakePacketConn{
		local:  testAddr(local),
		reads:  make(chan packet, 4),
		writes: make(chan packet, 4),
		closed: make(chan struct{}),
	}
}

func (c *fakePacketConn) Read(b []byte) (int, error) {
	n, _, err := c.ReadFrom(b)
	return n, err
}

func (c *fakePacketConn) Write(b []byte) (int, error) {
	return c.WriteTo(b, testAddr("127.0.0.1:0"))
}

func (c *fakePacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	c.deadlineMutex.Lock()
	deadline := c.readDeadline
	c.deadlineMutex.Unlock()
	var timeout <-chan time.Time
	if !deadline.IsZero() {
		duration := time.Until(deadline)
		if duration <= 0 {
			return 0, nil, timeoutError{}
		}
		timer := time.NewTimer(duration)
		defer timer.Stop()
		timeout = timer.C
	}
	select {
	case value := <-c.reads:
		return copy(b, value.data), value.addr, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	case <-timeout:
		return 0, nil, timeoutError{}
	}
}

func (c *fakePacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	data := append([]byte(nil), b...)
	select {
	case c.writes <- packet{data: data, addr: addr}:
	case <-c.closed:
		return 0, net.ErrClosed
	}
	if c.onWrite != nil {
		c.onWrite(data, addr)
	}
	return len(data), nil
}

func (c *fakePacketConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *fakePacketConn) LocalAddr() net.Addr  { return c.local }
func (c *fakePacketConn) RemoteAddr() net.Addr { return testAddr("127.0.0.1:0") }

func (c *fakePacketConn) SetDeadline(deadline time.Time) error {
	c.deadlineMutex.Lock()
	c.readDeadline = deadline
	c.writeDeadline = deadline
	c.deadlineMutex.Unlock()
	return nil
}

func (c *fakePacketConn) SetReadDeadline(deadline time.Time) error {
	c.deadlineMutex.Lock()
	c.readDeadline = deadline
	c.deadlineMutex.Unlock()
	return nil
}

func (c *fakePacketConn) SetWriteDeadline(deadline time.Time) error {
	c.deadlineMutex.Lock()
	c.writeDeadline = deadline
	c.deadlineMutex.Unlock()
	return nil
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "test deadline exceeded" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func newTestProxy(dialer any) *Proxy {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	switch dialer := dialer.(type) {
	case nil:
		return New(logger, nil)
	case func(string, string) (net.Conn, error):
		return New(logger, dialFunc(dialer))
	case interface {
		Dial(string, string) (net.Conn, error)
	}:
		return New(logger, dialer)
	default:
		panic(fmt.Sprintf("unsupported test dialer %T", dialer))
	}
}

func waitForSignal(t *testing.T, signal <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(testTimeout):
		t.Fatalf("timed out waiting for %s", name)
	}
}

func TestServeTCPCloseDoesNotHandleNilConnection(t *testing.T) {
	var dialCalls atomic.Int32
	p := newTestProxy(func(network, address string) (net.Conn, error) {
		dialCalls.Add(1)
		return nil, errors.New("unexpected dial")
	})
	t.Cleanup(func() { _ = p.Close() })
	listener := newCloseListener()
	serveDone := make(chan error, 1)
	go func() { serveDone <- p.serveTCP(listener) }()

	waitForSignal(t, p.TCPReady(), "TCP listener readiness")
	if err := p.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}

	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("serveTCP() error = %v", err)
		}
	case <-time.After(testTimeout):
		t.Fatal("serveTCP did not stop after Close")
	}
	if got := dialCalls.Load(); got != 0 {
		t.Fatalf("dial calls after listener close = %d, want 0", got)
	}
}

func TestServeUDPReadyAndClose(t *testing.T) {
	p := newTestProxy(func(network, address string) (net.Conn, error) {
		return nil, errors.New("unexpected dial")
	})
	t.Cleanup(func() { _ = p.Close() })
	packetConn := newFakePacketConn("127.0.0.1:10000")
	serveDone := make(chan error, 1)
	go func() { serveDone <- p.serveUDP(packetConn) }()

	waitForSignal(t, p.UDPReady(), "UDP listener readiness")
	if got := p.UDPPort(); got != 10000 {
		t.Fatalf("UDPPort() = %d, want 10000", got)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("serveUDP() error = %v", err)
		}
	case <-time.After(testTimeout):
		t.Fatal("serveUDP did not stop after Close")
	}
}

func TestRelayTCPExactBidirectionalPayload(t *testing.T) {
	request := []byte("local tcp request")
	response := []byte("local tcp response")
	local := newScriptedConn(request)
	upstream := newScriptedConn(response)
	t.Cleanup(func() { _ = local.Close() })
	t.Cleanup(func() { _ = upstream.Close() })
	deadline := time.Now().Add(testTimeout)
	if err := local.SetDeadline(deadline); err != nil {
		t.Fatalf("local.SetDeadline() error = %v", err)
	}
	if err := upstream.SetDeadline(deadline); err != nil {
		t.Fatalf("upstream.SetDeadline() error = %v", err)
	}

	if err := RelayTCP(local, upstream); err != nil {
		t.Fatalf("RelayTCP() error = %v", err)
	}
	if got := upstream.written.Bytes(); !bytes.Equal(got, request) {
		t.Fatalf("relayed request = %q (n=%d), want %q (n=%d)", got, len(got), request, len(request))
	}
	if got := local.written.Bytes(); !bytes.Equal(got, response) {
		t.Fatalf("relayed response = %q (n=%d), want %q (n=%d)", got, len(got), response, len(response))
	}
	if !local.writeClosed.Load() || !upstream.writeClosed.Load() {
		t.Fatalf("CloseWrite calls = local:%v upstream:%v, want both true", local.writeClosed.Load(), upstream.writeClosed.Load())
	}
}

func TestHandleUDPLocalSessionExactPayload(t *testing.T) {
	request := []byte("local udp request")
	response := []byte("local udp response")
	target := "127.0.0.1:40000"
	clientAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 30000}
	upstream := newFakePacketConn("127.0.0.1:20000")
	upstream.onWrite = func(_ []byte, addr net.Addr) {
		upstream.reads <- packet{data: response, addr: addr}
	}
	proxySocket := newFakePacketConn("127.0.0.1:10000")

	p := newTestProxy(func(network, address string) (net.Conn, error) {
		if network != "udp" || address != target {
			return nil, errors.New("unexpected UDP dial target")
		}
		return upstream, nil
	})
	p.udpConn = proxySocket
	p.AllocProjection(target)
	t.Cleanup(func() {
		p.nm.Remove(clientAddr.String())
		_ = p.Close()
	})

	if err := p.handleUDP(clientAddr, request); err != nil {
		t.Fatalf("handleUDP() error = %v", err)
	}
	upstreamWrite := waitForPacket(t, upstream.writes, "UDP upstream request")
	if !bytes.Equal(upstreamWrite.data, request) || len(upstreamWrite.data) != len(request) {
		t.Fatalf("UDP upstream request = %q (n=%d), want %q (n=%d)", upstreamWrite.data, len(upstreamWrite.data), request, len(request))
	}
	clientWrite := waitForPacket(t, proxySocket.writes, "UDP client response")
	if !bytes.Equal(clientWrite.data, response) || len(clientWrite.data) != len(response) {
		t.Fatalf("UDP client response = %q (n=%d), want %q (n=%d)", clientWrite.data, len(clientWrite.data), response, len(response))
	}
	if clientWrite.addr.String() != clientAddr.String() {
		t.Fatalf("UDP response address = %q, want %q", clientWrite.addr, clientAddr)
	}
	upstream.deadlineMutex.Lock()
	readDeadline := upstream.readDeadline
	upstream.deadlineMutex.Unlock()
	if readDeadline.IsZero() {
		t.Fatal("UDP upstream read deadline was not set")
	}
	proxySocket.deadlineMutex.Lock()
	writeDeadline := proxySocket.writeDeadline
	proxySocket.deadlineMutex.Unlock()
	if writeDeadline.IsZero() {
		t.Fatal("UDP proxy write deadline was not set")
	}
}

func TestForwardDNSMessageExactLengthDeadlineAndClose(t *testing.T) {
	name := dnsmessage.MustNewName("example.test.")
	query := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 42, RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET,
		}},
	}
	queryBytes, err := query.Pack()
	if err != nil {
		t.Fatalf("query.Pack() error = %v", err)
	}
	response := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: query.ID, Response: true},
		Questions: query.Questions,
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30},
			Body:   &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}},
		}},
	}
	responseBytes, err := response.Pack()
	if err != nil {
		t.Fatalf("response.Pack() error = %v", err)
	}
	conn := newScriptedConn(responseBytes)
	dialCalls := 0
	dial := func(network, address string, timeout time.Duration) (net.Conn, error) {
		dialCalls++
		if network != "udp" || address != "127.0.0.1:53" || timeout != testTimeout {
			t.Fatalf("dial args = (%q, %q, %v), want (udp, 127.0.0.1:53, %v)", network, address, timeout, testTimeout)
		}
		return conn, nil
	}

	got, parsed, err := forwardDNSMessageWithDial("127.0.0.1:53", queryBytes, testTimeout, dial)
	if err != nil {
		t.Fatalf("forwardDNSMessageWithDial() error = %v", err)
	}
	if dialCalls != 1 {
		t.Fatalf("DNS dial calls = %d, want 1", dialCalls)
	}
	if written := conn.written.Bytes(); !bytes.Equal(written, queryBytes) || len(written) != len(queryBytes) {
		t.Fatalf("DNS query = %x (n=%d), want %x (n=%d)", written, len(written), queryBytes, len(queryBytes))
	}
	if len(got) != len(responseBytes) || !bytes.Equal(got, responseBytes) {
		t.Fatalf("DNS response = %x (n=%d), want %x (n=%d)", got, len(got), responseBytes, len(responseBytes))
	}
	if len(parsed.Answers) != 1 {
		t.Fatalf("parsed answer count = %d, want 1", len(parsed.Answers))
	}
	if conn.deadline.IsZero() {
		t.Fatal("DNS connection deadline was not set")
	}
	if !conn.closed.Load() {
		t.Fatal("DNS connection was not closed")
	}
}

func TestDialContextUnwrapsProductionWrapperAndTakesPriority(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	t.Cleanup(func() { _ = server.Close() })
	inner := &preferredContextDialer{conn: client}
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	p := New(logger, ggdialer.NewDialer(inner, true, "test", "test", "test"))
	t.Cleanup(func() { _ = p.Close() })

	conn, err := p.dialContext(p.ctx, "tcp", "127.0.0.1:443")
	if err != nil {
		t.Fatalf("dialContext() error = %v", err)
	}
	if conn != client {
		t.Fatalf("dialContext() connection = %v, want wrapped context dialer's connection", conn)
	}
	if got := inner.dialContextCalls.Load(); got != 1 {
		t.Fatalf("DialContext calls = %d, want 1", got)
	}
	if got := inner.dialCalls.Load(); got != 0 {
		t.Fatalf("plain Dial calls = %d, want 0", got)
	}
}

func TestDNSDialTrackedHonorsPerCallTimeout(t *testing.T) {
	p := newTestProxy(nil)
	t.Cleanup(func() { _ = p.Close() })
	deadlineSeen := make(chan time.Time, 1)
	p.dnsDial = func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "udp" || address != "127.0.0.1:53" {
			return nil, fmt.Errorf("unexpected DNS dial: %s %s", network, address)
		}
		deadline, _ := ctx.Deadline()
		deadlineSeen <- deadline
		<-ctx.Done()
		return nil, ctx.Err()
	}
	const timeout = 25 * time.Millisecond
	started := time.Now()
	conn, err := p.dialTracked(p.ctx, "udp", "127.0.0.1:53", timeout)
	if conn != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("dialTracked() = (%v, %v), want (nil, %v)", conn, err, context.DeadlineExceeded)
	}
	deadline := waitForResult(t, deadlineSeen, "DNS per-call deadline")
	if deadline.IsZero() || deadline.Before(started) || deadline.After(started.Add(timeout+50*time.Millisecond)) {
		t.Fatalf("DNS dial deadline = %v, want approximately %v", deadline, started.Add(timeout))
	}
	if elapsed := time.Since(started); elapsed > testTimeout {
		t.Fatalf("DNS dial timeout returned after %v, want within %v", elapsed, testTimeout)
	}
}

func waitForPacket(t *testing.T, packets <-chan packet, name string) packet {
	t.Helper()
	select {
	case value := <-packets:
		return value
	case <-time.After(testTimeout):
		t.Fatalf("timed out waiting for %s", name)
		return packet{}
	}
}
