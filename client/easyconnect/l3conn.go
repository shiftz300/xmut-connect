package easyconnect

import (
	"context"
	"io"
	"net"
	"sync"

	"github.com/mythologyli/zju-connect/log"
)

type L3Conn struct {
	easyConnectClient *Client
	ctx               context.Context
	cancel            context.CancelFunc

	send l3Stream
	recv l3Stream
}

type l3Stream struct {
	mu      sync.Mutex
	conn    net.Conn
	unwatch func() bool
	retries int
}

func (s *l3Stream) set(ctx context.Context, conn net.Conn) {
	s.conn = conn
	s.unwatch = context.AfterFunc(ctx, func() { _ = conn.Close() })
}

func (s *l3Stream) close() {
	if s.conn != nil {
		s.unwatch()
		_ = s.conn.Close()
		s.conn = nil
	}
}

func (c *L3Conn) run(stream *l3Stream, packet []byte, transfer func(net.Conn, []byte) (int, error), reconnect func() (net.Conn, error)) (int, error) {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	for {
		if c.ctx.Err() != nil || stream.conn == nil {
			return 0, net.ErrClosed
		}
		n, err := transfer(stream.conn, packet)
		if err == nil || n > 0 || stream.retries >= 5 || c.ctx.Err() != nil {
			return n, err
		}
		log.Print("L3 stream interrupted, retrying")
		stream.close()
		stream.retries++
		conn, err := reconnect()
		if err != nil {
			return 0, err
		}
		stream.set(c.ctx, conn)
	}
}

func (c *L3Conn) Read(p []byte) (int, error) {
	return c.run(&c.recv, p, net.Conn.Read, func() (net.Conn, error) {
		return c.easyConnectClient.recvConn(c.ctx)
	})
}

func (c *L3Conn) Write(p []byte) (int, error) {
	return c.run(&c.send, p, net.Conn.Write, func() (net.Conn, error) {
		return c.easyConnectClient.sendConn(c.ctx)
	})
}

func (c *L3Conn) Close() error {
	c.cancel()
	for _, stream := range []*l3Stream{&c.send, &c.recv} {
		stream.mu.Lock()
		stream.close()
		stream.mu.Unlock()
	}
	return nil
}

func (c *Client) NewL3Conn() (io.ReadWriteCloser, error) {
	ctx, cancel := context.WithCancel(c.lifecycleCtx)
	l3 := &L3Conn{easyConnectClient: c, ctx: ctx, cancel: cancel}
	send, err := c.sendConn(ctx)
	if err != nil {
		cancel()
		return nil, err
	}
	l3.send.set(ctx, send)

	recv, err := c.recvConn(ctx)
	if err != nil {
		_ = l3.Close()
		return nil, err
	}
	l3.recv.set(ctx, recv)
	return l3, nil
}
