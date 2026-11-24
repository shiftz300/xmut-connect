package service

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mythologyli/zju-connect/dial"
	"github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

func TestManagedShadowsocksTCPUDPAndRelease(t *testing.T) {
	// In this test client and server share the library's process-wide salt
	// filter. Separate deployed processes each use their own filter.
	t.Setenv("SHADOWSOCKS_SF_CAPACITY", "0")
	const password = "test-shadowsocks-password"
	cipher, err := core.PickCipher("aes-128-gcm", nil, password)
	if err != nil {
		t.Fatal(err)
	}
	echoTCP, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoTCP.Close()
	go func() {
		conn, err := echoTCP.Accept()
		if err == nil {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		}
	}()
	echoUDP, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoUDP.Close()
	go func() {
		buf := make([]byte, 128)
		n, peer, err := echoUDP.ReadFrom(buf)
		if err == nil {
			_, _ = echoUDP.WriteTo(buf[:n], peer)
		}
	}()

	dialer := dial.NewDialer(nil, nil, nil, false, "")
	reserved, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reserved.Addr().String()
	_ = reserved.Close()
	closer, err := StartManagedShadowsocks(context.Background(), dialer, "ss://aes-128-gcm:"+password+"@"+address)
	if err != nil {
		t.Fatal(err)
	}
	defer closer()

	wire, err := net.DialTimeout("tcp4", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer wire.Close()
	_ = wire.SetDeadline(time.Now().Add(2 * time.Second))
	stream := cipher.StreamConn(wire)
	if _, err := stream.Write(append(socks.ParseAddr(echoTCP.Addr().String()), "tcp"...)); err != nil {
		t.Fatal(err)
	}
	var reply [3]byte
	if _, err := io.ReadFull(stream, reply[:]); err != nil || string(reply[:]) != "tcp" {
		t.Fatalf("Shadowsocks TCP reply %q, error %v", reply, err)
	}

	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	_ = packet.SetDeadline(time.Now().Add(2 * time.Second))
	udp := cipher.PacketConn(packet)
	peer, err := net.ResolveUDPAddr("udp4", address)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := udp.WriteTo(append(socks.ParseAddr(echoUDP.LocalAddr().String()), "udp"...), peer); err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 512)
	n, _, err := udp.ReadFrom(frame)
	if err != nil {
		t.Fatal(err)
	}
	target := socks.SplitAddr(frame[:n])
	if target.String() != echoUDP.LocalAddr().String() || string(frame[len(target):n]) != "udp" {
		t.Fatalf("Shadowsocks UDP reply %x", frame[:n])
	}

	closer()
	reopened, err := StartManagedShadowsocks(context.Background(), dialer, "ss://aes-128-gcm:"+password+"@"+address)
	if err != nil {
		t.Fatalf("Shadowsocks ports not released: %v", err)
	}
	reopened()
}
