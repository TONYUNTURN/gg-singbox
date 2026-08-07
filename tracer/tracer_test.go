package tracer

import (
	"io"
	"syscall"
	"testing"

	"github.com/sirupsen/logrus"
)

func newUnitTestTracer() *Tracer {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	return &Tracer{
		log:        logger,
		storehouse: MakeStorehouse(),
		socketInfo: make(map[int]map[int]SocketMetadata),
	}
}

func TestTracerSocketMetadataLifecycle(t *testing.T) {
	tracer := newUnitTestTracer()
	want := SocketMetadata{Family: syscall.AF_INET, Type: syscall.SOCK_STREAM, Protocol: syscall.IPPROTO_TCP}

	tracer.saveSocketInfo(100, 7, want)
	got := tracer.getSocketInfo(100, 7)
	if got == nil || *got != want {
		t.Fatalf("getSocketInfo() = %#v, want %#v", got, want)
	}
	tracer.removeSocketInfo(100, 7)
	if got := tracer.getSocketInfo(100, 7); got != nil {
		t.Fatalf("getSocketInfo() after remove = %#v, want nil", got)
	}
}

func TestTracerNetworkClassification(t *testing.T) {
	tracer := newUnitTestTracer()
	tests := []struct {
		name     string
		metadata SocketMetadata
		want     string
	}{
		{name: "IPv4 TCP", metadata: SocketMetadata{Family: syscall.AF_INET, Type: syscall.SOCK_STREAM, Protocol: syscall.IPPROTO_TCP}, want: "tcp"},
		{name: "IPv6 UDP", metadata: SocketMetadata{Family: syscall.AF_INET6, Type: syscall.SOCK_DGRAM, Protocol: syscall.IPPROTO_UDP}, want: "udp"},
		{name: "local socket", metadata: SocketMetadata{Family: syscall.AF_LOCAL, Type: syscall.SOCK_STREAM}, want: ""},
		{name: "unsupported protocol", metadata: SocketMetadata{Family: syscall.AF_INET, Type: syscall.SOCK_STREAM, Protocol: syscall.IPPROTO_UDP}, want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tracer.network(&tt.metadata); got != tt.want {
				t.Errorf("network(%#v) = %q, want %q", tt.metadata, got, tt.want)
			}
		})
	}
}

func TestStorehouseLifecycle(t *testing.T) {
	storehouse := MakeStorehouse()
	storehouse.Save(100, syscall.SYS_CONNECT, []uint64{7, 8, 9})

	got, ok := storehouse.Get(100, syscall.SYS_CONNECT)
	if !ok {
		t.Fatal("Get() found no saved syscall arguments")
	}
	args, ok := got.([]uint64)
	if !ok || len(args) != 3 || args[0] != 7 || args[2] != 9 {
		t.Fatalf("Get() = %#v, want []uint64{7, 8, 9}", got)
	}
	storehouse.Remove(100, syscall.SYS_CONNECT)
	if _, ok := storehouse.Get(100, syscall.SYS_CONNECT); ok {
		t.Fatal("Get() found syscall arguments after Remove")
	}
}
