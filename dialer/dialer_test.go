package dialer

import (
	"net"
	"sync/atomic"
	"testing"
)

type closeableDialer struct {
	closeCalls atomic.Int32
}

func (d *closeableDialer) Dial(network, address string) (net.Conn, error) {
	return nil, net.UnknownNetworkError(network)
}

func (d *closeableDialer) Close() error {
	d.closeCalls.Add(1)
	return nil
}

func TestDialerSupportUDPAndClose(t *testing.T) {
	inner := &closeableDialer{}
	d := NewDialer(inner, true, "local", "fake", "fake://local")

	if !d.SupportUDP() {
		t.Error("SupportUDP() = false, want true")
	}
	if err := d.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if got := inner.closeCalls.Load(); got != 1 {
		t.Fatalf("inner Close() calls = %d, want 1", got)
	}
}
