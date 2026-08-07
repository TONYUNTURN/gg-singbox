package dialer

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

type contextDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

func newDirectContextDialer(t *testing.T, fullCone bool) contextDialer {
	t.Helper()
	d, ok := NewDirect(fullCone).(contextDialer)
	if !ok {
		t.Fatal("direct dialer does not implement DialContext")
	}
	return d
}

func TestDirectDialContextCanceled(t *testing.T) {
	for _, tc := range []struct {
		name     string
		network  string
		fullCone bool
	}{
		{name: "tcp", network: "tcp"},
		{name: "udp", network: "udp"},
		{name: "full-cone udp", network: "udp", fullCone: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			t.Cleanup(cancel)
			cancel()

			conn, err := newDirectContextDialer(t, tc.fullCone).DialContext(ctx, tc.network, "127.0.0.1:1")
			if conn != nil {
				_ = conn.Close()
				t.Fatal("DialContext() returned a connection for a canceled context")
			}
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("DialContext() error = %v, want context.Canceled", err)
			}
		})
	}
}

func TestDirectDialContextTCP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	conn, err := newDirectContextDialer(t, false).DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
}

func TestDirectDialContextUDP(t *testing.T) {
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = packetConn.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	conn, err := newDirectContextDialer(t, false).DialContext(ctx, "udp", packetConn.LocalAddr().String())
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	udpConn, ok := conn.(*directUDPConn)
	if !ok || udpConn.FullCone {
		t.Fatalf("DialContext() connection = %#v, want symmetric directUDPConn", conn)
	}
}

func TestDirectDialContextFullConeUDP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	conn, err := newDirectContextDialer(t, true).DialContext(ctx, "udp", "127.0.0.1:1")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	udpConn, ok := conn.(*directUDPConn)
	if !ok || !udpConn.FullCone {
		t.Fatalf("DialContext() connection = %#v, want full-cone directUDPConn", conn)
	}
	if udpConn.LocalAddr() == nil {
		t.Fatal("DialContext() full-cone connection has no local address")
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestDirectDialContextUnknownNetwork(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	conn, err := newDirectContextDialer(t, false).DialContext(ctx, "unknown", "127.0.0.1:1")
	if conn != nil {
		_ = conn.Close()
		t.Fatal("DialContext() returned a connection for an unknown network")
	}
	var unknownNetworkError net.UnknownNetworkError
	if !errors.As(err, &unknownNetworkError) {
		t.Fatalf("DialContext() error = %T(%v), want net.UnknownNetworkError", err, err)
	}
}
