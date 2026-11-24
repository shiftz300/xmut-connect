//go:build !tun

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/mythologyli/zju-connect/client/authchallenge"
	"github.com/mythologyli/zju-connect/client/easyconnect"
	"github.com/mythologyli/zju-connect/configs"
	"github.com/mythologyli/zju-connect/dial"
	"github.com/mythologyli/zju-connect/internal/management"
	"github.com/mythologyli/zju-connect/service"
	"github.com/mythologyli/zju-connect/stack/gvisor"
	"github.com/mythologyli/zju-connect/underlay"
)

func runManagement(cfg configs.Config) error {
	unlock, err := lockManagementInstance()
	if err != nil {
		return err
	}
	defer unlock()
	tlsCert, err := readEasyConnectCertificate(cfg)
	if err != nil {
		return errors.New("could not load EasyConnect certificate")
	}
	address := net.JoinHostPort(cfg.ServerAddress, strconv.Itoa(cfg.ServerPort))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	controller := management.NewController(management.Options{
		Server: address, Version: zjuConnectVersionString(),
		SMSWait:        time.Duration(cfg.SMSWaitTimeout) * time.Second,
		HealthInterval: time.Duration(cfg.HealthInterval) * time.Second,
		LoginCooldown:  15 * time.Second,
		Notify:         management.Webhook(ctx, cfg.WebhookURL),
		Authenticate: func(ctx context.Context, sms func(context.Context) (string, error), authenticated func()) (management.Session, error) {
			base, err := underlay.New(underlay.Options{
				InterfaceName: cfg.BindInterface, AutoDetect: cfg.AutoDetectInterface, LocalDNSServer: cfg.LocalDNSServer,
			})
			if err != nil {
				return nil, err
			}
			session := &managedSession{cfg: cfg, underlay: base, expired: make(chan struct{})}
			session.client = easyconnect.NewClient(easyconnect.Options{
				Context: ctx,
				Server:  address,
				Auth: easyconnect.AuthOptions{
					Username: cfg.Username, Password: cfg.Password, Certificate: tlsCert, TOTPSecret: cfg.TOTPSecret,
				},
				Resources:        easyconnect.ResourceOptions{Fetch: true, IncludeDomains: !cfg.SkipDomainResource},
				UnderlayDialer:   base,
				ChallengeHandler: managedChallenge{sms: sms},
				OnSessionExpired: session.markExpired,
				OnAuthenticated: func() {
					session.authenticated = true
					authenticated()
				},
			})
			err = session.client.Authenticate()
			switch {
			case errors.Is(err, easyconnect.ErrSMSRejected):
				err = management.ErrSMSRejected
			case errors.Is(err, easyconnect.ErrSangforShutdown), errors.Is(err, easyconnect.ErrSessionExpired):
				err = management.ErrExpired
			}
			return session, err
		},
	})

	listener, err := net.Listen("tcp", cfg.ManagementBind)
	if err != nil {
		return fmt.Errorf("management listener: %w", err)
	}
	server := &http.Server{
		Handler: management.NewHTTPHandler(controller, management.HTTPOptions{
			Token: cfg.ManagementToken, Origin: cfg.ManagementOrigin, WebUI: cfg.ManagementWebUI,
		}),
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()
	fmt.Fprintln(os.Stdout, "management INFO listening on", listener.Addr())

	var result error
	select {
	case <-ctx.Done():
	case err := <-serveErr:
		if !errors.Is(err, http.ErrServerClosed) {
			result = errors.New("management HTTP listener stopped unexpectedly")
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		_ = server.Close()
	}
	controller.Close()
	fmt.Fprintln(os.Stdout, "management INFO stopped")
	return result
}

type managedChallenge struct {
	authchallenge.UnsupportedHandler
	sms func(context.Context) (string, error)
}

func (h managedChallenge) HandleCodeChallengeContext(ctx context.Context, challenge authchallenge.CodeChallenge) (authchallenge.CodeResponse, error) {
	if challenge.Kind != authchallenge.CodeSMS {
		return authchallenge.CodeResponse{}, management.ErrUnsupported
	}
	code, err := h.sms(ctx)
	return authchallenge.CodeResponse{Code: code}, err
}

func (managedChallenge) HandleTextCaptcha(authchallenge.TextCaptchaChallenge) (authchallenge.TextCaptchaResponse, error) {
	return authchallenge.TextCaptchaResponse{}, management.ErrUnsupported
}

type managedSession struct {
	cfg           configs.Config
	underlay      *underlay.Dialer
	client        *easyconnect.Client
	expired       chan struct{}
	expireOnce    sync.Once
	authenticated bool
	prepared      bool
}

func (s *managedSession) markExpired() {
	s.expireOnce.Do(func() { close(s.expired) })
}

func (s *managedSession) Expired() <-chan struct{} { return s.expired }

func (s *managedSession) IP() string {
	ip, err := s.client.IP()
	if err != nil {
		return ""
	}
	return ip.String()
}

func (s *managedSession) Close(ctx context.Context, logout bool) error {
	s.client.Close()
	defer s.underlay.Close()
	if logout && s.authenticated {
		if err := s.client.Logout(ctx); err != nil {
			return management.ErrLogout
		}
	}
	return nil
}

func (s *managedSession) Open(parent context.Context) (management.Tunnel, error) {
	if !s.prepared {
		if err := s.client.PrepareTunnel(); err != nil {
			if errors.Is(err, easyconnect.ErrSangforShutdown) || errors.Is(err, easyconnect.ErrSessionExpired) {
				return nil, management.ErrExpired
			}
			return nil, err
		}
		s.prepared = true
	}
	cfg := s.cfg
	cfg.TCPTunnelMode = cfg.TCPTunnelMode || s.client.CanUseTCPTunnel()
	base, err := configureTunnel(cfg, s.client)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	tunnel := &managedTunnel{
		cancel: cancel, fail: make(chan error, 1), resourceURL: cfg.HealthCheckURL,
		probe: &http.Client{
			Transport: &http.Transport{
				DialContext: base.dialer.DialVPN, DisableKeepAlives: true, TLSHandshakeTimeout: 5 * time.Second,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	tunnel.closers = append(tunnel.closers, base.resolver.Close)
	if l3, ok := base.stack.(*gvisor.Stack); ok {
		closer, err := l3.StartManaged(func(err error) {
			if errors.Is(err, easyconnect.ErrSangforShutdown) {
				s.markExpired()
				err = management.ErrExpired
			}
			select {
			case tunnel.fail <- err:
			default:
			}
		})
		if err != nil {
			tunnel.Close()
			if errors.Is(err, easyconnect.ErrSangforShutdown) {
				return nil, management.ErrExpired
			}
			return nil, err
		}
		tunnel.closers = append(tunnel.closers, closer)
	}

	err = tunnel.startProxies(ctx, base, cfg)
	if err != nil {
		tunnel.Close()
		return nil, err
	}
	if !cfg.DisableKeepAlive && (cfg.KeepAliveURL != "" || base.useRemoteDNS) {
		done := make(chan struct{})
		go func() {
			defer close(done)
			service.KeepAlive(ctx, base.resolver, base.dialer, cfg.KeepAliveURL)
		}()
		tunnel.closers = append(tunnel.closers, func() { <-done })
	}
	return tunnel, nil
}

type managedTunnel struct {
	cancel      context.CancelFunc
	closers     []func()
	fail        chan error
	probe       *http.Client
	resourceURL string
	services    management.Services
}

func (t *managedTunnel) startProxies(ctx context.Context, base *configuredTunnel, cfg configs.Config) error {
	if cfg.ShadowsocksURL != "" {
		closeProxy, err := service.StartManagedShadowsocks(ctx, base.dialer, cfg.ShadowsocksURL)
		if err != nil {
			return errors.New("Shadowsocks listener could not start")
		}
		t.closers = append(t.closers, closeProxy)
		t.services.Shadowsocks = true
	}
	if cfg.SocksBind != "" {
		closeProxy, err := service.StartManagedSOCKS5(ctx, cfg.SocksBind, base.dialer, base.resolver, cfg.SocksUser, cfg.SocksPasswd)
		if err != nil {
			return errors.New("SOCKS5 listener could not start")
		}
		t.closers = append(t.closers, closeProxy)
		t.services.SOCKS5 = true
	}
	if cfg.HTTPBind != "" {
		closeProxy, err := service.StartManagedHTTP(ctx, cfg.HTTPBind, base.dialer)
		if err != nil {
			return errors.New("HTTP proxy listener could not start")
		}
		t.closers = append(t.closers, closeProxy)
		t.services.HTTP = true
	}
	return nil
}

func (t *managedTunnel) Probe(ctx context.Context) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.resourceURL, nil)
	if err != nil {
		return 0, management.ErrProbeTarget
	}
	resp, err := t.probe.Do(req)
	if err != nil {
		var dns *net.DNSError
		switch {
		case errors.Is(err, easyconnect.ErrSangforShutdown), errors.Is(err, easyconnect.ErrSessionExpired):
			return 0, management.ErrExpired
		case errors.As(err, &dns):
			return 0, management.ErrDNS
		case errors.Is(err, dial.ErrACLDenied):
			return 0, management.ErrProbeTarget
		default:
			return 0, management.ErrNetwork
		}
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return resp.StatusCode, nil
	}
	return resp.StatusCode, management.ErrProbeResponse
}

func (t *managedTunnel) Failure() <-chan error         { return t.fail }
func (t *managedTunnel) Services() management.Services { return t.services }

func (t *managedTunnel) Close() {
	t.cancel()
	t.probe.CloseIdleConnections()
	for i := len(t.closers) - 1; i >= 0; i-- {
		t.closers[i]()
	}
}
