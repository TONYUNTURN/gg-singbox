package singbox

import (
	"context"
	"fmt"
	"net"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/mzz2017/gg/dialer"
)

// SingBoxDialer wraps a sing-box adapter.Outbound as a gg dialer.Dialer.
type SingBoxDialer struct {
	outbound   adapter.Outbound
	supportUDP bool
	box        interface{ Close() error }
	name       string
	protocol   string
	link       string
}

// NewSingBoxDialer creates a SingBoxDialer from a sing-box outbound.
func NewSingBoxDialer(outbound adapter.Outbound, box interface{ Close() error }, name, protocol, link string) *dialer.Dialer {
	supportUDP := false
	for _, netw := range outbound.Network() {
		if netw == N.NetworkUDP {
			supportUDP = true
			break
		}
	}
	sbd := &SingBoxDialer{
		outbound:   outbound,
		supportUDP: supportUDP,
		box:        box,
		name:       name,
		protocol:   protocol,
		link:       link,
	}
	return dialer.NewDialer(sbd, supportUDP, name, protocol, link)
}

// Dial implements proxy.Dialer.
func (d *SingBoxDialer) Dial(network, addr string) (net.Conn, error) {
	ctx := context.Background()
	socksaddr := M.ParseSocksaddr(addr)

	switch network {
	case "tcp":
		return d.outbound.DialContext(ctx, N.NetworkTCP, socksaddr)
	case "udp":
		if !d.supportUDP {
			return nil, fmt.Errorf("outbound %s does not support UDP", d.outbound.Tag())
		}
		pc, err := d.outbound.ListenPacket(ctx, socksaddr)
		if err != nil {
			return nil, fmt.Errorf("ListenPacket: %w", err)
		}
		return &udpPacketConnAdapter{PacketConn: pc}, nil
	default:
		return nil, net.UnknownNetworkError(network)
	}
}

// Close shuts down the underlying sing-box Box.
func (d *SingBoxDialer) Close() error {
	if d.box != nil {
		return d.box.Close()
	}
	return nil
}

// udpPacketConnAdapter wraps net.PacketConn to satisfy net.Conn,
// so that proxy/udp.go's type assertion `c.(net.PacketConn)` succeeds.
type udpPacketConnAdapter struct {
	net.PacketConn
}

func (c *udpPacketConnAdapter) Read(b []byte) (int, error) {
	n, _, err := c.PacketConn.ReadFrom(b)
	return n, err
}

func (c *udpPacketConnAdapter) Write(b []byte) (int, error) {
	return 0, fmt.Errorf("udpPacketConnAdapter.Write: use WriteTo instead")
}

func (c *udpPacketConnAdapter) RemoteAddr() net.Addr {
	return dummyAddr{}
}

func (c *udpPacketConnAdapter) LocalAddr() net.Addr {
	return c.PacketConn.LocalAddr()
}

type dummyAddr struct{}

func (d dummyAddr) Network() string { return "udp" }
func (d dummyAddr) String() string  { return "0.0.0.0:0" }
