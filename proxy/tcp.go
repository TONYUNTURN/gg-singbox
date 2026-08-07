package proxy

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
)

func (p *Proxy) handleTCP(conn net.Conn) error {
	defer conn.Close()
	loopback, _ := netip.AddrFromSlice(conn.LocalAddr().(*net.TCPAddr).IP)
	tgt := p.GetProjection(loopback)
	if tgt == "" {
		return fmt.Errorf("mapped target address not found: %v", loopback)
	}
	p.log.Tracef("received tcp: %v, tgt: %v", conn.RemoteAddr().String(), tgt)
	c, err := p.dialContext(p.ctx, "tcp", tgt)
	if err != nil {
		return fmt.Errorf("dial TCP target %s: %w", tgt, err)
	}
	if c == nil {
		return errors.New("dial TCP target returned a nil connection")
	}
	if !p.trackConn(c) {
		_ = c.Close()
		return ErrProxyClosed
	}
	defer func() {
		_ = c.Close()
		p.untrackConn(c)
	}()
	if err = RelayTCP(conn, c); err != nil {
		// ignore benign connection termination signals
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) ||
			strings.Contains(err.Error(), "broken pipe") {
			return nil
		}
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return nil
		}
		return fmt.Errorf("handleTCP relay error: %w", err)
	}
	return nil
}

type WriteCloser interface {
	CloseWrite() error
}

func RelayTCP(lConn, rConn net.Conn) (err error) {
	// Each direction needs its own buffer because both copies run concurrently.
	lToRBuf := make([]byte, 256*1024)
	rToLBuf := make([]byte, 256*1024)
	eCh := make(chan error, 2)
	go func() {
		_, e := io.CopyBuffer(rConn, lConn, lToRBuf)
		if rConn, ok := rConn.(WriteCloser); ok {
			if closeErr := rConn.CloseWrite(); e == nil {
				e = closeErr
			}
		}
		eCh <- e
	}()
	go func() {
		_, e := io.CopyBuffer(lConn, rConn, rToLBuf)
		if lConn, ok := lConn.(WriteCloser); ok {
			if closeErr := lConn.CloseWrite(); e == nil {
				e = closeErr
			}
		}
		eCh <- e
	}()
	first := <-eCh
	if first != nil {
		_ = lConn.Close()
		_ = rConn.Close()
	}
	second := <-eCh
	if first != nil {
		return first
	}
	return second
}
