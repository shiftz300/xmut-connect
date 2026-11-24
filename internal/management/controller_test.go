package management

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type testSession struct {
	expired chan struct{}
	closed  chan bool
	tunnel  *testTunnel
	opens   atomic.Int32
}

func newTestSession() *testSession {
	return &testSession{
		expired: make(chan struct{}),
		closed:  make(chan bool, 1),
		tunnel:  &testTunnel{fail: make(chan error, 1)},
	}
}

func (s *testSession) Open(context.Context) (Tunnel, error) {
	s.opens.Add(1)
	return s.tunnel, nil
}
func (s *testSession) Expired() <-chan struct{} { return s.expired }
func (s *testSession) IP() string               { return "192.0.2.10" }
func (s *testSession) Close(_ context.Context, logout bool) error {
	s.closed <- logout
	return nil
}

type testTunnel struct {
	fail  chan error
	probe func(context.Context) error
}

func (t *testTunnel) Probe(ctx context.Context) error {
	if t.probe != nil {
		return t.probe(ctx)
	}
	return nil
}
func (t *testTunnel) Failure() <-chan error { return t.fail }
func (t *testTunnel) Services() Services    { return Services{Shadowsocks: true} }
func (t *testTunnel) Close()                {}

func waitStatus(t *testing.T, c *Controller, matches func(Status) bool) Status {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		status := c.Status()
		if matches(status) {
			return status
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("unexpected final status: %+v", c.Status())
	return Status{}
}

func waitState(t *testing.T, c *Controller, state State) Status {
	t.Helper()
	return waitStatus(t, c, func(status Status) bool { return status.State == state })
}

func TestCancelAndSMSTimeoutRetireChallenge(t *testing.T) {
	c := NewController(Options{
		SMSWait: 200 * time.Millisecond,
		Authenticate: func(ctx context.Context, sms func(context.Context) (string, error), _ func()) (Session, error) {
			_, err := sms(ctx)
			return nil, err
		},
	})
	defer c.Close()
	if err := c.Login(); err != nil {
		t.Fatal(err)
	}
	first := waitState(t, c, WaitingSMS)
	if err := c.Cancel("wrong"); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale cancel returned %v", err)
	}
	if err := c.Cancel(first.AttemptID); err != nil {
		t.Fatal(err)
	}
	waitState(t, c, Disconnected)
	if err := c.Login(); err != nil {
		t.Fatal(err)
	}
	second := waitState(t, c, WaitingSMS)
	if first.ChallengeID == second.ChallengeID || first.AttemptID == second.AttemptID {
		t.Fatal("authentication IDs were reused")
	}
	if err := c.SubmitSMS(first.ChallengeID, "123456"); !errors.Is(err, ErrStaleChallenge) {
		t.Fatalf("stale code returned %v", err)
	}
	failure := waitState(t, c, Failed)
	if failure.Error != "sms_timeout" || failure.ChallengeID != "" || failure.AttemptID != "" {
		t.Fatalf("incorrect timeout status: %+v", failure)
	}
	if err := c.SubmitSMS(second.ChallengeID, "123456"); !errors.Is(err, ErrStaleChallenge) {
		t.Fatalf("expired code returned %v", err)
	}
}

func TestTunnelRecoveryExpiryAndLogout(t *testing.T) {
	first, second := newTestSession(), newTestSession()
	var authCalls atomic.Int32
	c := NewController(Options{
		RetryDelay: time.Millisecond,
		Authenticate: func(ctx context.Context, sms func(context.Context) (string, error), authenticated func()) (Session, error) {
			switch authCalls.Add(1) {
			case 1:
				authenticated()
				return first, nil
			case 2:
				if _, err := sms(ctx); err != nil {
					return nil, err
				}
				authenticated()
				return second, nil
			default:
				return nil, errors.New("unexpected repeated authentication")
			}
		},
	})
	defer c.Close()
	if err := c.Login(); err != nil {
		t.Fatal(err)
	}
	waitState(t, c, Connected)
	first.tunnel.fail <- errors.New("temporary transport failure")
	waitStatus(t, c, func(s Status) bool { return first.opens.Load() == 2 && s.State == Connected })
	if authCalls.Load() != 1 {
		t.Fatal("network failure triggered authentication")
	}
	close(first.expired)
	waiting := waitState(t, c, WaitingSMS)
	if <-first.closed {
		t.Fatal("attempted to log out an expired session")
	}
	if err := c.SubmitSMS(waiting.ChallengeID, "123456"); err != nil {
		t.Fatal(err)
	}
	connected := waitState(t, c, Connected)
	if connected.Health.Status != "healthy" || connected.VirtualIP == "" || connected.LastAuth == nil {
		t.Fatalf("incomplete connected status: %+v", connected)
	}
	if err := c.Logout(); err != nil {
		t.Fatal(err)
	}
	waitState(t, c, Disconnected)
	if !<-second.closed {
		t.Fatal("did not request gateway logout")
	}
	if authCalls.Load() != 2 {
		t.Fatal("logout caused another authentication")
	}
}

func TestHealthDoesNotInferSuccessFromListeners(t *testing.T) {
	session := newTestSession()
	var probeCalls atomic.Int32
	session.tunnel.probe = func(context.Context) error {
		if probeCalls.Add(1) <= 3 {
			return ErrDNS
		}
		return nil
	}
	c := NewController(Options{
		RetryDelay: time.Millisecond, HealthInterval: 100 * time.Millisecond,
		Authenticate: func(_ context.Context, _ func(context.Context) (string, error), done func()) (Session, error) {
			done()
			return session, nil
		},
	})
	defer c.Close()
	if err := c.Login(); err != nil {
		t.Fatal(err)
	}
	status := waitStatus(t, c, func(s Status) bool { return s.Health.Status == "dns_failure" && probeCalls.Load() >= 3 })
	if status.State == Connected || !status.Services.Shadowsocks || status.Health.LastSuccess != nil {
		t.Fatalf("unexpected unhealthy status: %+v", status)
	}
	waitState(t, c, Connected)
	if session.opens.Load() != 1 {
		t.Fatal("DNS failure unnecessarily rebuilt the tunnel")
	}
}

func TestNetworkRecoveryIsBounded(t *testing.T) {
	session := newTestSession()
	session.tunnel.probe = func(context.Context) error { return ErrNetwork }
	var authCalls atomic.Int32
	c := NewController(Options{
		RetryDelay: time.Millisecond,
		Authenticate: func(_ context.Context, _ func(context.Context) (string, error), done func()) (Session, error) {
			authCalls.Add(1)
			done()
			return session, nil
		},
	})
	defer c.Close()
	if err := c.Login(); err != nil {
		t.Fatal(err)
	}
	status := waitState(t, c, Failed)
	if status.Error != "network_failure" || status.Services.Shadowsocks ||
		session.opens.Load() != 4 || authCalls.Load() != 1 {
		t.Fatalf("unexpected recovery result: %+v, opens=%d", status, session.opens.Load())
	}
}

func TestExplicitReconnectClosesOldSessionBeforeAuthenticating(t *testing.T) {
	first, second := newTestSession(), newTestSession()
	var authCalls atomic.Int32
	c := NewController(Options{
		Authenticate: func(ctx context.Context, sms func(context.Context) (string, error), authenticated func()) (Session, error) {
			if authCalls.Add(1) == 1 {
				authenticated()
				return first, nil
			}
			select {
			case logout := <-first.closed:
				if !logout {
					return nil, errors.New("reconnect skipped gateway logout")
				}
			default:
				return nil, errors.New("started authentication before releasing the old session")
			}
			if _, err := sms(ctx); err != nil {
				return nil, err
			}
			authenticated()
			return second, nil
		},
	})
	defer c.Close()
	if err := c.Login(); err != nil {
		t.Fatal(err)
	}
	waitState(t, c, Connected)
	if err := c.Reconnect(); err != nil {
		t.Fatal(err)
	}
	waiting := waitState(t, c, WaitingSMS)
	if err := c.SubmitSMS(waiting.ChallengeID, "123456"); err != nil {
		t.Fatal(err)
	}
	waitState(t, c, Connected)
	if authCalls.Load() != 2 {
		t.Fatal("expected exactly one replacement authentication")
	}
}

func TestRejectedTunnelDoesNotTriggerRepeatedSMS(t *testing.T) {
	var authCalls atomic.Int32
	c := NewController(Options{
		Authenticate: func(_ context.Context, _ func(context.Context) (string, error), done func()) (Session, error) {
			authCalls.Add(1)
			session := newTestSession()
			session.tunnel.probe = func(context.Context) error { return ErrExpired }
			done()
			return session, nil
		},
	})
	defer c.Close()
	if err := c.Login(); err != nil {
		t.Fatal(err)
	}
	waitStatus(t, c, func(s Status) bool { return s.State == Expired && !s.Active })
	if authCalls.Load() != 2 {
		t.Fatal("unusable session triggered repeated authentication")
	}
}
