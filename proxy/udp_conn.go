package proxy

import (
	"net"
	"sync"
	"time"
)

type UDPConn struct {
	Establishing chan struct{}
	Timeout      time.Duration
	Target       net.Addr
	Err          error
	waiters      int
	net.PacketConn
	closeOnce sync.Once
}

func NewUDPConn(conn net.PacketConn) *UDPConn {
	c := &UDPConn{
		PacketConn:   conn,
		Establishing: make(chan struct{}),
	}
	if c.PacketConn != nil {
		close(c.Establishing)
	}
	return c
}

type UDPConnMapping struct {
	nm map[string]*UDPConn
	sync.Mutex
}

func NewUDPConnMapping() *UDPConnMapping {
	m := &UDPConnMapping{
		nm: make(map[string]*UDPConn),
	}
	return m
}

func (m *UDPConnMapping) Get(key string) (conn *UDPConn, ok bool) {
	v, ok := m.nm[key]
	if ok {
		conn = v
	}
	return
}

// pass val=nil for stating it is establishing
func (m *UDPConnMapping) Insert(key string, val net.PacketConn) *UDPConn {
	c := NewUDPConn(val)
	m.nm[key] = c
	return c
}

func (m *UDPConnMapping) Remove(key string) {
	m.remove(key, nil, nil)
}

func (m *UDPConnMapping) RemoveIf(key string, expected *UDPConn) {
	m.remove(key, expected, nil)
}

func (m *UDPConnMapping) remove(key string, expected *UDPConn, err error) {
	m.Lock()
	conn, ok := m.nm[key]
	if !ok || expected != nil && conn != expected {
		m.Unlock()
		return
	}
	delete(m.nm, key)
	m.Unlock()
	conn.close(err)
}

func (m *UDPConnMapping) CloseAll(err error) {
	m.Lock()
	connections := make([]*UDPConn, 0, len(m.nm))
	for key, conn := range m.nm {
		delete(m.nm, key)
		connections = append(connections, conn)
	}
	m.Unlock()
	for _, conn := range connections {
		conn.close(err)
	}
}

func (c *UDPConn) close(err error) {
	c.closeOnce.Do(func() {
		select {
		case <-c.Establishing:
		default:
			if err != nil && c.Err == nil {
				c.Err = err
			}
			close(c.Establishing)
		}
		if c.PacketConn != nil {
			_ = c.PacketConn.Close()
		}
	})
}
