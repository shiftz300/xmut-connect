// The following code part comes from go-shadowsocks2
// Original code can be found at https://github.com/shadowsocks/go-shadowsocks2
// This code is covered by the Apache License 2.0. See https://github.com/shadowsocks/go-shadowsocks2/blob/master/LICENSE

package service

import (
	"context"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/mythologyli/zju-connect/dial"
	"github.com/mythologyli/zju-connect/internal/hook_func"
	"github.com/mythologyli/zju-connect/log"
	"github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

const udpBufSize = 64 * 1024
const udpTimeout = 5 * time.Minute

func parseURL(s string) (addr, cipher, password string, err error) {
	u, err := url.Parse(s)
	if err != nil {
		return
	}

	addr = u.Host
	if u.User != nil {
		cipher = u.User.Username()
		password, _ = u.User.Password()
	}
	return
}

func ServeShadowsocks(dialer *dial.Dialer, address string) {
	run, closeListener, err := shadowsocksListener(context.Background(), dialer, address)
	if err != nil {
		log.Fatal(err)
	}
	hook_func.RegisterTerminalFunc("CloseShadowsocksListener", func(context.Context) error {
		closeListener()
		return nil
	})
	run()
}

func StartManagedShadowsocks(ctx context.Context, dialer *dial.Dialer, address string) (func(), error) {
	run, closeListener, err := shadowsocksListener(ctx, dialer, address)
	if err != nil {
		return nil, err
	}
	go run()
	return closeListener, nil
}

func shadowsocksListener(ctx context.Context, dialer *dial.Dialer, address string) (run func(), closeListener func(), err error) {
	addr, cipher, password, err := parseURL(address)
	if err != nil {
		return nil, nil, err
	}
	ciph, err := core.PickCipher(cipher, nil, password)
	if err != nil {
		return nil, nil, err
	}
	tcpListener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, err
	}
	// Use the actual TCP port when the caller requested an ephemeral port.
	udpPacketConn, err := net.ListenPacket("udp", tcpListener.Addr().String())
	if err != nil {
		_ = tcpListener.Close()
		return nil, nil, err
	}
	log.Printf("Shadowsocks server listening on %s", tcpListener.Addr())
	ctx, cancel := context.WithCancel(ctx)
	var loops sync.WaitGroup
	loops.Add(2)
	run = func() {
		go func() {
			defer loops.Done()
			tcpRemote(ctx, scopedListener{tcpListener, ctx}, ciph.StreamConn, dialer, &loops)
		}()
		defer loops.Done()
		udpRemote(ctx, udpPacketConn, ciph.PacketConn, dialer, &loops)
	}
	return run, func() {
		cancel()
		_ = tcpListener.Close()
		_ = udpPacketConn.Close()
		loops.Wait()
	}, nil
}

func tcpRemote(ctx context.Context, l net.Listener, shadow func(net.Conn) net.Conn, dialer *dial.Dialer, workers *sync.WaitGroup) {
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				log.Println("Shadowsocks TCP server closed")
				return
			}

			log.Printf("failed to accept: %v", err)
			continue
		}

		workers.Go(func() {
			defer c.Close()
			sc := shadow(c)

			tgt, err := socks.ReadAddr(sc)
			if err != nil {
				log.Printf("failed to get target address from %v: %v", c.RemoteAddr(), err)
				// drain c to avoid leaking server behavioral features
				// see https://www.ndss-symposium.org/ndss-paper/detecting-probe-resistant-proxies/
				_, err = io.Copy(io.Discard, c)
				if err != nil {
					log.Printf("discard error: %v", err)
				}
				return
			}

			rc, err := dialer.Dial(ctx, "tcp", tgt.String())
			if err != nil {
				log.Printf("failed to connect to target: %v", err)
				return
			}
			rc = scopeConn(ctx, rc)
			defer rc.Close()

			log.Printf("[SS][TCP] %s <-> %s", c.RemoteAddr(), tgt)
			if err = relay(sc, rc); err != nil {
				log.DebugPrintf("SS TCP relay error: %v", err)
			}
		})
	}
}

// relay copies between left and right bidirectionally
func relay(left, right net.Conn) error {
	var err, err1 error
	var wg sync.WaitGroup
	var wait = 5 * time.Second
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err1 = io.Copy(right, left)
		_ = right.SetReadDeadline(time.Now().Add(wait)) // unblock read on right
	}()
	_, err = io.Copy(left, right)
	_ = left.SetReadDeadline(time.Now().Add(wait)) // unblock read on left
	wg.Wait()
	if err1 != nil && !errors.Is(err1, os.ErrDeadlineExceeded) { // requires Go 1.15+
		return err1
	}
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		return err
	}
	return nil
}

// Listen on addr for encrypted packets and basically do UDP NAT.
func udpRemote(ctx context.Context, c net.PacketConn, shadow func(net.PacketConn) net.PacketConn, dialer *dial.Dialer, workers *sync.WaitGroup) {
	defer func(c net.PacketConn) {
		_ = c.Close()
	}(c)
	c = shadow(c)

	nm := newNATMap(udpTimeout)
	buf := make([]byte, udpBufSize)

	for {
		n, raddr, err := c.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				log.Println("Shadowsocks UDP server closed")
				return
			}

			log.Printf("UDP remote read error: %v", err)
			continue
		}

		targetAddr := socks.SplitAddr(buf[:n])
		if targetAddr == nil {
			log.Print("failed to split Shadowsocks target address")
			continue
		}

		payload := buf[len(targetAddr):n]

		targetConn := nm.Get(raddr.String())
		if targetConn == nil {
			targetConn, err = dialer.Dial(ctx, "udp", targetAddr.String())
			if err != nil {
				log.Printf("UDP remote listen error: %v", err)
				continue
			}

			targetConn = scopeConn(ctx, targetConn)
			nm.Add(raddr, targetConn)
			workers.Go(func() {
				_ = udpServerToClientCopy(c, raddr, targetConn, nm.timeout)
				nm.Del(raddr.String())
				targetConn.Close()
			})
		}

		log.Printf("[SS][UDP] %s <-> %s", raddr, targetAddr)
		_, err = targetConn.Write(payload) // accept only UDPAddr despite the signature
		if err != nil {
			log.Printf("UDP remote write error: %v", err)
			continue
		}
	}
}

// Packet NAT table
type udpNATMap struct {
	sync.RWMutex
	m       map[string]net.Conn
	timeout time.Duration
}

func newNATMap(timeout time.Duration) *udpNATMap {
	m := &udpNATMap{}
	m.m = make(map[string]net.Conn)
	m.timeout = timeout
	return m
}

func (m *udpNATMap) Get(key string) net.Conn {
	m.RLock()
	defer m.RUnlock()
	return m.m[key]
}

func (m *udpNATMap) Set(key string, targetConn net.Conn) {
	m.Lock()
	defer m.Unlock()

	m.m[key] = targetConn
}

func (m *udpNATMap) Del(key string) net.Conn {
	m.Lock()
	defer m.Unlock()

	targetConn, ok := m.m[key]
	if ok {
		delete(m.m, key)
		return targetConn
	}
	return nil
}

func (m *udpNATMap) Add(peer net.Addr, targetConn net.Conn) {
	m.Set(peer.String(), targetConn)
}

func udpServerToClientCopy(c net.PacketConn, peer net.Addr, targetConn net.Conn, timeout time.Duration) error {
	buf := make([]byte, udpBufSize)

	for {
		_ = targetConn.SetReadDeadline(time.Now().Add(timeout))
		n, err := targetConn.Read(buf)
		if err != nil {
			return err
		}

		// server -> client: add original packet source
		srcAddr := socks.ParseAddr(targetConn.RemoteAddr().String())
		copy(buf[len(srcAddr):], buf[:n])
		copy(buf, srcAddr)
		_, err = c.WriteTo(buf[:len(srcAddr)+n], peer)

		if err != nil {
			return err
		}
	}
}
