package management

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

type State string

const (
	Disconnected   State = "disconnected"
	Authenticating State = "authenticating"
	WaitingSMS     State = "waiting_sms"
	Connecting     State = "connecting"
	Connected      State = "connected"
	Reconnecting   State = "reconnecting"
	Expired        State = "expired"
	Failed         State = "error"
)

var (
	ErrConflict       = errors.New("state_conflict")
	ErrStaleChallenge = errors.New("stale_challenge")
	ErrSMSTimeout     = errors.New("sms_timeout")
	ErrSMSRejected    = errors.New("sms_rejected")
	ErrUnsupported    = errors.New("unsupported_challenge")
	ErrExpired        = errors.New("session_expired")
	ErrDNS            = errors.New("dns_failure")
	ErrNetwork        = errors.New("network_failure")
	ErrProbeTarget    = errors.New("health_target_not_allowed")
	ErrProbeResponse  = errors.New("health_unexpected_response")
	ErrCooldown       = errors.New("login_rate_limited")
	ErrLogout         = errors.New("gateway_logout_unconfirmed")
)

type Services struct {
	Shadowsocks bool `json:"shadowsocks"`
	SOCKS5      bool `json:"socks5"`
	HTTP        bool `json:"http"`
}

type Health struct {
	Status      string     `json:"status"`
	LastCheck   *time.Time `json:"last_check,omitempty"`
	LastSuccess *time.Time `json:"last_success,omitempty"`
}

type Status struct {
	State            State      `json:"state"`
	Server           string     `json:"server"`
	Version          string     `json:"version"`
	AttemptID        string     `json:"attempt_id,omitempty"`
	ChallengeID      string     `json:"challenge_id,omitempty"`
	ChallengeExpires *time.Time `json:"challenge_expires,omitempty"`
	ConnectedSince   *time.Time `json:"connected_since,omitempty"`
	ConnectedSeconds int64      `json:"connected_seconds"`
	LastAuth         *time.Time `json:"last_auth,omitempty"`
	VirtualIP        string     `json:"virtual_ip,omitempty"`
	Services         Services   `json:"services"`
	Health           Health     `json:"health"`
	Error            string     `json:"error,omitempty"`
	Active           bool       `json:"active"`
	Stopping         bool       `json:"stopping"`
}

type Tunnel interface {
	Probe(context.Context) error
	Failure() <-chan error
	Services() Services
	Close()
}

type Session interface {
	Open(context.Context) (Tunnel, error)
	Expired() <-chan struct{}
	IP() string
	Close(context.Context, bool) error
}

type Authenticate func(ctx context.Context, sms func(context.Context) (string, error), authenticated func()) (Session, error)

type Options struct {
	Server, Version string
	SMSWait         time.Duration
	HealthInterval  time.Duration
	LoginCooldown   time.Duration
	RetryDelay      time.Duration
	Authenticate    Authenticate
	Notify          func(Event)
}

type startReason uint8

const (
	operatorLogin startReason = iota
	operatorReconnect
	sessionExpired
)

type attempt struct {
	id           string
	ctx          context.Context
	cancel       context.CancelFunc
	stop         string
	wait         chan string
	wasConnected bool
	reason       startReason
}

type Controller struct {
	mu        sync.Mutex
	options   Options
	status    Status
	active    *attempt
	nextLogin time.Time
	closed    bool
	workers   sync.WaitGroup
	events    eventLog
}

func NewController(options Options) *Controller {
	if options.SMSWait <= 0 {
		options.SMSWait = 3 * time.Minute
	}
	if options.HealthInterval <= 0 {
		options.HealthInterval = time.Minute
	}
	if options.RetryDelay <= 0 {
		options.RetryDelay = 2 * time.Second
	}
	return &Controller{options: options, status: Status{
		State: Disconnected, Server: options.Server, Version: options.Version, Health: Health{Status: "idle"},
	}}
}

func (c *Controller) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	status := c.status
	status.Active = c.active != nil
	if status.ConnectedSince != nil {
		status.ConnectedSeconds = int64(time.Since(*status.ConnectedSince) / time.Second)
	}
	return status
}

func (c *Controller) Login() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active != nil || c.closed {
		return ErrConflict
	}
	if time.Now().Before(c.nextLogin) {
		return ErrCooldown
	}
	c.startLocked(operatorLogin)
	return nil
}

func (c *Controller) Reconnect() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ErrConflict
	}
	if c.active != nil {
		if c.active.stop != "" || c.status.AttemptID != "" {
			return ErrConflict
		}
		if time.Now().Before(c.nextLogin) {
			return ErrCooldown
		}
		c.stopLocked("reconnect")
		return nil
	}
	if time.Now().Before(c.nextLogin) {
		return ErrCooldown
	}
	c.startLocked(operatorReconnect)
	return nil
}

func (c *Controller) Cancel(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active == nil || id == "" || id != c.status.AttemptID || c.active.stop != "" {
		return ErrConflict
	}
	c.stopLocked("cancel")
	return nil
}

func (c *Controller) Logout() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active == nil {
		c.transitionLocked(Disconnected, "", "")
		return nil
	}
	if c.active.stop != "" {
		return ErrConflict
	}
	c.stopLocked("logout")
	return nil
}

func (c *Controller) Close() {
	c.mu.Lock()
	c.closed = true
	if c.active != nil {
		c.stopLocked("logout")
	}
	c.mu.Unlock()
	c.workers.Wait()
}

func (c *Controller) stopLocked(action string) {
	c.active.stop = action
	c.status.Stopping = true
	c.clearChallengeLocked()
	c.active.cancel()
}

func (c *Controller) SubmitSMS(id, code string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active == nil || c.status.State != WaitingSMS || id == "" ||
		c.status.ChallengeID != id || c.active.wait == nil ||
		!time.Now().Before(*c.status.ChallengeExpires) {
		return ErrStaleChallenge
	}
	c.active.wait <- code
	c.clearChallengeLocked()
	c.transitionLocked(Authenticating, "", "")
	return nil
}

func newID() string {
	var id [16]byte
	rand.Read(id[:]) // crypto/rand.Read always fills or terminates the process.
	return hex.EncodeToString(id[:])
}

func (c *Controller) startLocked(reason startReason) {
	ctx, cancel := context.WithCancel(context.Background())
	a := &attempt{id: newID(), ctx: ctx, cancel: cancel, reason: reason}
	c.active = a
	c.nextLogin = time.Now().Add(c.options.LoginCooldown)
	c.status.AttemptID = a.id
	c.status.Health.Status = "idle"
	if reason != operatorLogin {
		c.transitionLocked(Reconnecting, "", "")
	} else {
		c.transitionLocked(Authenticating, "", "")
	}
	c.workers.Add(1)
	go c.run(a)
}

func (c *Controller) clearChallengeLocked() {
	c.active.wait = nil
	c.status.ChallengeID = ""
	c.status.ChallengeExpires = nil
}

func (c *Controller) sms(a *attempt, ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, c.options.SMSWait)
	defer cancel()
	c.mu.Lock()
	if a.ctx.Err() != nil || ctx.Err() != nil {
		c.mu.Unlock()
		return "", context.Canceled
	}
	wait := make(chan string, 1)
	a.wait = wait
	expires, _ := ctx.Deadline()
	c.nextLogin = time.Now().Add(c.options.LoginCooldown)
	c.status.ChallengeID = newID()
	c.status.ChallengeExpires = &expires
	c.transitionLocked(WaitingSMS, "", "sms_required")
	c.mu.Unlock()
	select {
	case code := <-wait:
		if err := ctx.Err(); err != nil {
			if a.ctx.Err() != nil {
				return "", a.ctx.Err()
			}
			return "", ErrSMSTimeout
		}
		return code, nil
	case <-ctx.Done():
		if a.ctx.Err() != nil {
			return "", a.ctx.Err()
		}
		return "", ErrSMSTimeout
	}
}

func (c *Controller) run(a *attempt) {
	defer c.workers.Done()
	session, err := c.options.Authenticate(a.ctx, func(ctx context.Context) (string, error) {
		return c.sms(a, ctx)
	}, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if a.ctx.Err() == nil {
			now := time.Now()
			c.status.LastAuth = &now
			c.transitionLocked(Connecting, "", "")
		}
	})
	authorized := err == nil
	if authorized {
		err = c.runSession(a, session)
	}
	isExpired := errors.Is(err, ErrExpired)
	if isExpired {
		c.mu.Lock()
		if a.stop == "" {
			c.transitionLocked(Expired, "session_expired", "session_expired")
		}
		c.mu.Unlock()
	}

	var closeErr error
	if session != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		closeErr = session.Close(ctx, !isExpired)
		cancel()
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	a.cancel()
	c.clearChallengeLocked()
	c.active = nil
	c.status.AttemptID = ""
	c.status.Stopping = false
	c.status.ConnectedSince = nil
	c.status.VirtualIP = ""
	c.status.Services = Services{}
	c.status.Health.Status = "idle"
	switch {
	case a.stop == "reconnect" && !c.closed:
		if closeErr != nil {
			c.recordLocked("WARN", "gateway_logout_unconfirmed")
		}
		c.startLocked(operatorReconnect)
	case a.stop != "" || c.closed:
		message := ""
		if closeErr != nil {
			message = "gateway_logout_unconfirmed"
			c.recordLocked("WARN", message)
		}
		c.transitionLocked(Disconnected, message, "")
	case isExpired:
		// Retry an explicitly expired session once. A replacement that
		// never became usable cannot start another automatic login.
		if authorized && (a.reason != sessionExpired || a.wasConnected) {
			c.startLocked(sessionExpired)
		}
	default:
		code := errorCode(err, "connection_failed")
		event := "severe_error"
		if code == "sms_timeout" || code == "sms_rejected" || code == "unsupported_challenge" {
			event = ""
		}
		c.status.Health.Status = errorCode(err, "unavailable")
		c.transitionLocked(Failed, code, event)
	}
}

func (c *Controller) runSession(a *attempt, session Session) error {
	const maxAttempts = 4
	for tries := 0; tries < maxAttempts; tries++ {
		select {
		case <-a.ctx.Done():
			return a.ctx.Err()
		case <-session.Expired():
			return ErrExpired
		default:
		}
		tunnel, err := session.Open(a.ctx)
		if err == nil {
			c.mu.Lock()
			c.status.Health.Status = "pending"
			c.status.VirtualIP = session.IP()
			c.status.Services = tunnel.Services()
			c.mu.Unlock()
			var healthy bool
			healthy, err = c.monitor(a, session, tunnel)
			tunnel.Close()
			if healthy {
				tries = 0
			}
		}
		c.mu.Lock()
		c.status.Services = Services{}
		c.status.ConnectedSince = nil
		c.status.VirtualIP = ""
		c.mu.Unlock()
		if errors.Is(err, ErrExpired) || a.ctx.Err() != nil {
			return err
		}
		select {
		case <-session.Expired():
			return ErrExpired
		default:
		}
		if tries == maxAttempts-1 {
			c.mu.Lock()
			c.recordLocked("WARN", "tunnel_unavailable")
			c.notifyLocked("tunnel_unavailable")
			c.mu.Unlock()
			return err
		}
		c.mu.Lock()
		c.status.Health.Status = errorCode(err, "tunnel_interrupted")
		c.transitionLocked(Reconnecting, c.status.Health.Status, "")
		c.mu.Unlock()
		timer := time.NewTimer(c.options.RetryDelay << tries)
		select {
		case <-timer.C:
		case <-session.Expired():
			timer.Stop()
			return ErrExpired
		case <-a.ctx.Done():
			timer.Stop()
			return a.ctx.Err()
		}
	}
	return ErrNetwork
}

func (c *Controller) monitor(a *attempt, session Session, tunnel Tunnel) (bool, error) {
	var healthy bool
	var failures int
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-a.ctx.Done():
			return healthy, a.ctx.Err()
		case <-session.Expired():
			return healthy, ErrExpired
		case err := <-tunnel.Failure():
			return healthy, err
		case <-timer.C:
		}

		ctx, cancel := context.WithTimeout(a.ctx, 8*time.Second)
		err := tunnel.Probe(ctx)
		cancel()
		if a.ctx.Err() != nil {
			return healthy, a.ctx.Err()
		}
		if errors.Is(err, ErrExpired) {
			return healthy, ErrExpired
		}

		now := time.Now()
		c.mu.Lock()
		c.status.Health.LastCheck = &now
		if err == nil {
			failures = 0
			healthy = true
			a.wasConnected = true
			c.status.Health.Status = "healthy"
			c.status.Health.LastSuccess = &now
			first := c.status.ConnectedSince == nil
			if first {
				c.status.ConnectedSince = &now
				c.status.AttemptID = ""
				c.transitionLocked(Connected, "", "connected")
			} else {
				c.transitionLocked(Connected, "", "")
			}
			c.mu.Unlock()
			timer.Reset(c.options.HealthInterval)
			continue
		}
		failures++
		c.status.Health.Status = errorCode(err, "network_failure")
		c.transitionLocked(Reconnecting, c.status.Health.Status, "")
		if failures == 3 && (errors.Is(err, ErrDNS) || errors.Is(err, ErrProbeResponse) || errors.Is(err, ErrProbeTarget)) {
			c.recordLocked("WARN", "tunnel_unavailable")
			c.notifyLocked("tunnel_unavailable")
		}
		c.mu.Unlock()
		if failures >= 3 {
			if errors.Is(err, ErrDNS) || errors.Is(err, ErrProbeResponse) || errors.Is(err, ErrProbeTarget) {
				timer.Reset(c.options.HealthInterval)
				continue
			}
			return healthy, err
		}
		timer.Reset(c.options.RetryDelay << (failures - 1))
	}
}

func errorCode(err error, fallback string) string {
	for _, known := range []error{ErrSMSTimeout, ErrSMSRejected, ErrUnsupported, ErrExpired, ErrDNS, ErrNetwork, ErrProbeTarget, ErrProbeResponse, ErrLogout} {
		if errors.Is(err, known) {
			return known.Error()
		}
	}
	return fallback
}
