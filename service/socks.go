package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/mythologyli/zju-connect/dial"
	"github.com/mythologyli/zju-connect/internal/hook_func"
	"github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/resolve"
	"github.com/things-go/go-socks5"
)

func ServeSocks5(bindAddr string, dialer *dial.Dialer, resolver *resolve.Resolver, user string, password string) {
	server := newSocks5(dialer.DialIPPort, resolver, user, password)
	log.Printf("SOCKS5 server listening on %s", bindAddr)

	listener, err := net.Listen("tcp", bindAddr)
	if err != nil {
		panic("SOCKS5 listen failed: " + err.Error())
	}

	hook_func.RegisterTerminalFunc("CloseSocks5Listener", func(ctx context.Context) error {
		log.Println("Closing SOCKS5 listener...")
		if err := listener.Close(); err != nil {
			return fmt.Errorf("close SOCKS5 listener failed: %w", err)
		}
		return nil
	})

	if err = server.Serve(listener); err != nil {
		if errors.Is(err, net.ErrClosed) {
			log.Println("SOCKS5 server closed")
		} else {
			log.Println("SOCKS5 listen failed: " + err.Error())
		}
	}
}

func newSocks5(dialContext func(context.Context, string, string) (net.Conn, error), resolver socks5.NameResolver, user, password string, extra ...socks5.Option) *socks5.Server {
	var authMethods []socks5.Authenticator
	if user != "" && password != "" {
		authMethods = append(authMethods, socks5.UserPassAuthenticator{
			Credentials: socks5.StaticCredentials{user: password},
		})

		log.Println("Neither traffic nor credentials are encrypted in the SOCKS5 protocol!")
		log.Println("DO NOT deploy it to the public network. All consequences and responsibilities have nothing to do with the developer")
	} else {
		authMethods = append(authMethods, socks5.NoAuthAuthenticator{})
	}

	options := []socks5.Option{
		socks5.WithAuthMethods(authMethods),
		socks5.WithResolver(resolver),
		socks5.WithDial(dialContext),
		socks5.WithLogger(socks5.NewLogger(log.NewLogger("[SOCKS5] "))),
	}
	return socks5.NewServer(append(options, extra...)...)

}

func StartManagedSOCKS5(ctx context.Context, bind string, dialer *dial.Dialer, resolver *resolve.Resolver, user, password string) (func(), error) {
	listener, err := net.Listen("tcp", bind)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	workers := &socksWorkers{}
	scopedDial := func(requestCtx context.Context, network, address string) (net.Conn, error) {
		dialCtx, cancel := context.WithCancel(requestCtx)
		defer cancel()
		stop := context.AfterFunc(ctx, cancel)
		defer stop()
		conn, err := dialer.DialIPPort(dialCtx, network, address)
		if err != nil {
			return nil, err
		}
		return scopeConn(ctx, conn), nil
	}
	server := newSocks5(scopedDial, scopedSocksResolver{resolver, ctx}, user, password, socks5.WithGPool(workers))
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.Serve(scopedListener{listener, ctx})
	}()
	return func() {
		cancel()
		_ = listener.Close()
		<-done
		workers.Wait()
	}, nil
}

type scopedSocksResolver struct {
	resolver *resolve.Resolver
	ctx      context.Context
}

func (r scopedSocksResolver) Resolve(_ context.Context, host string) (context.Context, net.IP, error) {
	return r.resolver.Resolve(r.ctx, host)
}

type socksWorkers struct{ sync.WaitGroup }

func (w *socksWorkers) Submit(run func()) error {
	w.Go(run)
	return nil
}
