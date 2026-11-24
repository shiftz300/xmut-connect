package service

import (
	"context"
	"net"
)

type scopedListener struct {
	net.Listener
	ctx context.Context
}

func (l scopedListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return scopeConn(l.ctx, conn), nil
}

type scopedConn struct {
	net.Conn
	stop func() bool
}

func (c *scopedConn) Close() error {
	c.stop()
	return c.Conn.Close()
}

func scopeConn(ctx context.Context, conn net.Conn) net.Conn {
	return &scopedConn{Conn: conn, stop: context.AfterFunc(ctx, func() { _ = conn.Close() })}
}
