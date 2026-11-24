package easyconnect

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/client/authchallenge"
	"github.com/mythologyli/zju-connect/internal/hook_func"
	"github.com/mythologyli/zju-connect/log"
	"inet.af/netaddr"
)

const (
	easyConnectHTTPTimeout           = 30 * time.Second
	easyConnectDialTimeout           = 10 * time.Second
	easyConnectResponseHeaderTimeout = 15 * time.Second
	easyConnectRawRequestTimeout     = 15 * time.Second
)

type AuthOptions struct {
	Username      string
	Password      string
	TOTPSecret    string
	Certificate   tls.Certificate
	GraphCodeFile string
}

type ResourceOptions struct {
	Fetch          bool
	IncludeDomains bool
}

type Options struct {
	Context          context.Context // When set, the caller owns client cleanup.
	OnAuthenticated  func()
	OnSessionExpired func()

	Server           string
	Auth             AuthOptions
	SessionID        string
	TestMultiLine    bool
	Resources        ResourceOptions
	UnderlayDialer   client.UnderlayDialer
	TLSKeyLogWriter  io.Writer
	ChallengeHandler authchallenge.Handler
}

type Client struct {
	server            string // Example: rvpn.zju.edu.cn:443. No protocol prefix
	username          string
	password          string
	totpSecret        string
	tlsCert           tls.Certificate
	testMultiLine     bool
	parseResource     bool
	useDomainResource bool
	tcpTunnelOnly     bool

	httpClient        *http.Client
	underlayDialer    client.UnderlayDialer
	tlsKeyLogWriter   io.Writer
	rawRequestTimeout time.Duration

	twfID string
	token *[48]byte

	lineList []string

	ipResources     []client.IPResource
	domainResources client.DomainResources
	ipSet           *netaddr.IPSet
	dnsResource     map[string][]net.IP
	dnsServer       string
	dnsServers      []string

	ip        net.IP // Client IP
	ipReverse []byte

	onAuthenticated    func()
	onSessionExpired   func()
	callerOwned        bool
	keepAliveWorkers   sync.WaitGroup
	keepAliveMu        sync.Mutex
	lifecycleCtx       context.Context
	lifecycleCancel    context.CancelFunc
	requestIPConn      net.Conn
	requestIPConnMu    sync.Mutex
	requestIPKeepAlive sync.Once
	keepAliveStarted   sync.Once
	closeOnce          sync.Once
	graphCodeFile      string
	challengeHandler   authchallenge.Handler
}

func NewClient(options Options) *Client {
	parent := options.Context
	if parent == nil {
		parent = context.Background()
	}
	lifecycleCtx, lifecycleCancel := context.WithCancel(parent)
	challengeHandler := options.ChallengeHandler
	if challengeHandler == nil {
		challengeHandler = authchallenge.NewCLIHandler(authchallenge.CLIOptions{})
	}
	c := &Client{
		server:            options.Server,
		callerOwned:       options.Context != nil,
		onAuthenticated:   options.OnAuthenticated,
		onSessionExpired:  options.OnSessionExpired,
		username:          options.Auth.Username,
		password:          options.Auth.Password,
		totpSecret:        options.Auth.TOTPSecret,
		tlsCert:           options.Auth.Certificate,
		testMultiLine:     options.TestMultiLine,
		parseResource:     options.Resources.Fetch,
		useDomainResource: options.Resources.IncludeDomains,
		httpClient:        &http.Client{Timeout: easyConnectHTTPTimeout},
		underlayDialer:    options.UnderlayDialer,
		tlsKeyLogWriter:   options.TLSKeyLogWriter,
		rawRequestTimeout: easyConnectRawRequestTimeout,
		twfID:             options.SessionID,
		lifecycleCtx:      lifecycleCtx,
		lifecycleCancel:   lifecycleCancel,
		graphCodeFile:     options.Auth.GraphCodeFile,
		challengeHandler:  challengeHandler,
	}
	c.setHTTPTransport(&tls.Config{InsecureSkipVerify: true})
	return c
}

// Close releases background resources held by the client. Safe to call
// multiple times.
func (c *Client) Close() {
	c.closeOnce.Do(func() {
		c.lifecycleCancel()
		c.httpClient.CloseIdleConnections()
		c.requestIPConnMu.Lock()
		if c.requestIPConn != nil {
			_ = c.requestIPConn.Close()
			c.requestIPConn = nil
		}
		c.requestIPConnMu.Unlock()
		c.keepAliveMu.Lock()
		c.keepAliveMu.Unlock()
		c.keepAliveWorkers.Wait()
	})
}

func (c *Client) IP() (net.IP, error) {
	if c.ip == nil {
		return nil, errors.New("IP not available")
	}

	return c.ip.To4(), nil
}

func (c *Client) IPSet() (*netaddr.IPSet, error) {
	if c.ipSet == nil {
		return nil, errors.New("IP set not available")
	}

	return c.ipSet, nil
}

func (c *Client) IPResources() ([]client.IPResource, error) {
	if c.ipResources == nil {
		return nil, errors.New("IP resources not available")
	}

	return c.ipResources, nil
}

func (c *Client) DomainResources() (client.DomainResources, error) {
	if c.domainResources == nil {
		return nil, errors.New("domain resources not available")
	}

	return c.domainResources, nil
}

func (c *Client) DNSResource() (map[string][]net.IP, error) {
	if c.dnsResource == nil {
		return nil, errors.New("DNS resource not available")
	}

	return c.dnsResource, nil
}

func (c *Client) DNSServer() (string, error) {
	if c.dnsServer == "" {
		return "", errors.New("DNS server not available")
	}

	return c.dnsServer, nil
}

func (c *Client) DNSServers() ([]string, error) {
	if len(c.dnsServers) == 0 {
		return nil, errors.New("DNS servers not available")
	}
	return append([]string(nil), c.dnsServers...), nil
}

func (c *Client) CanUseTCPTunnel() bool {
	return c.tcpTunnelOnly
}

func (c *Client) Setup() error {
	if err := c.Authenticate(); err != nil {
		return err
	}
	return c.PrepareTunnel()
}

// Authenticate obtains an authorized EasyConnect session using the configured
// challenge handler. Setup remains the combined entry point for CLI callers.
func (c *Client) Authenticate() error {
	if c.underlayDialer == nil {
		return errors.New("underlay dialer is required")
	}
	if err := c.ensureSession(); err != nil {
		return err
	}

	// Probe at most once. If the selected line changes, establish one fresh
	// session on that line before continuing setup.
	if c.testMultiLine {
		configStr, err := c.requestConfig()
		if err != nil {
			log.Printf("Error occurred while requesting config: %v", err)
		} else if err := c.parseLineListFromConfig(configStr); err != nil {
			log.Printf("Error occurred while parsing config: %v", err)
		} else {
			log.Printf("Line list: %v", c.lineList)

			bestLine, err := findBestLine(c.lineList, c.dialContext, c.tlsKeyLogWriter)
			if err != nil {
				log.Printf("Error occurred while finding best line: %v", err)
			} else {
				log.Printf("Best line: %v", bestLine)
				if c.server != bestLine {
					c.server = bestLine
					c.testMultiLine = false
					c.twfID = ""
					if err := c.ensureSession(); err != nil {
						return err
					}
				}
			}
		}
	}

	if c.onAuthenticated != nil {
		c.onAuthenticated()
	}
	return nil
}

// PrepareTunnel obtains the token, resources and IP for an authorized
// session. Transport failures can be retried without issuing a new SMS.
func (c *Client) PrepareTunnel() error {
	if c.twfID == "" {
		return errors.New("EasyConnect tunnel requires an authenticated session")
	}
	// Then, use the TwfID to get token
	err := c.requestToken()
	if err != nil {
		return err
	}

	startTime := time.Now()

	// Then we get the resources from server
	if c.parseResource {
		resources, err := c.requestResources()
		if err != nil {
			if c.callerOwned {
				return err
			}
			log.Printf("Error occurred while requesting resources: %v", err)
		} else {
			c.ipResources = nil
			if err := c.parseResources(resources); err != nil {
				// Missing DNS metadata is handled by the configured resolver.
				// The managed tunnel still needs a parsed resource policy.
				if c.callerOwned && c.ipResources == nil {
					return err
				}
				log.Printf("Error occurred while parsing resources: %v", err)
			}
		}
	}

	if c.tcpTunnelOnly {
		log.Println("Server disabled virtual IP allocation; using TCP tunnel")
	} else {
		// Error may occur if we request too fast
		if time.Since(startTime) < time.Second {
			timer := time.NewTimer(time.Second - time.Since(startTime))
			select {
			case <-timer.C:
			case <-c.lifecycleCtx.Done():
				timer.Stop()
				return c.lifecycleCtx.Err()
			}
		}

		// Finally, use the token to get client IP
		if err := c.requestIP(); err != nil {
			return err
		}
	}

	// Periodic session keepalive. Without this, sangfor servers with strict
	// idle policies (observed at HUST) close the session as idle, which
	// surfaces as "broken pipe" + "unexpected handshake reply" panics in
	// the L3 tunnel layer. The official EasyConnect client calls
	// /por/update_session.csp; we mirror that. Guarded by sync.Once so the
	// repeated Setup calls don't double-start it.
	c.keepAliveStarted.Do(func() {
		if !c.callerOwned {
			hook_func.RegisterTerminalFunc("CloseSessionKeepAlive", func(ctx context.Context) error {
				c.Close()
				return nil
			})
		}
		c.startKeepAliveWorker(c.sessionKeepAliveLoop)
	})

	return nil
}

func (c *Client) startKeepAliveWorker(run func()) {
	c.keepAliveMu.Lock()
	defer c.keepAliveMu.Unlock()
	if c.lifecycleCtx.Err() != nil {
		return
	}
	c.keepAliveWorkers.Add(1)
	go func() {
		defer c.keepAliveWorkers.Done()
		run()
	}()
}

func (c *Client) ensureSession() error {
	if c.twfID != "" {
		return nil
	}
	return c.requestTwfID(c.graphCodeFile)
}

func (c *Client) setHTTPTransport(tlsConfig *tls.Config) {
	if transport, ok := c.httpClient.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = c.dialContext
	if c.callerOwned {
		transport.Proxy = nil
	}
	transport.TLSClientConfig = tlsConfig.Clone()
	if c.tlsKeyLogWriter != nil {
		transport.TLSClientConfig.KeyLogWriter = c.tlsKeyLogWriter
	}
	transport.ResponseHeaderTimeout = easyConnectResponseHeaderTimeout
	c.httpClient.Transport = transport
}

func (c *Client) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if c.underlayDialer == nil {
		return (&net.Dialer{Timeout: easyConnectDialTimeout, KeepAlive: 30 * time.Second}).DialContext(ctx, network, address)
	}
	return c.underlayDialer.DialContext(ctx, network, address)
}

func (c *Client) rawRequestContext() (context.Context, context.CancelFunc) {
	return c.rawRequestContextFrom(c.lifecycleCtx)
}

func (c *Client) rawRequestContextFrom(parent context.Context) (context.Context, context.CancelFunc) {
	timeout := c.rawRequestTimeout
	if timeout <= 0 {
		timeout = easyConnectRawRequestTimeout
	}
	return context.WithTimeout(parent, timeout)
}

func armConnectionContext(ctx context.Context, conn net.Conn) (func(), error) {
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}
	stopCancel := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
	})
	return func() {
		stopCancel()
		_ = conn.SetDeadline(time.Time{})
	}, nil
}

func (c *Client) sessionKeepAliveLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	c.runSessionKeepAlive(ticker.C, 10*time.Second)
}

func (c *Client) runSessionKeepAlive(ticks <-chan time.Time, requestTimeout time.Duration) {
	for {
		select {
		case <-c.lifecycleCtx.Done():
			return
		case <-ticks:
			ctx, cancel := context.WithTimeout(c.lifecycleCtx, requestTimeout)
			err := c.requestUpdateSession(ctx)
			cancel()
			if err != nil {
				if err == errNotFound {
					log.Println("server does not support update_session, stopping keepalive")
					return
				}
				if errors.Is(err, ErrSessionExpired) && c.onSessionExpired != nil {
					c.onSessionExpired()
					return
				}
				log.Print("update_session keepalive failed")
			}
		}
	}
}
