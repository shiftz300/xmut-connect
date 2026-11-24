package easyconnect

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mythologyli/zju-connect/client/authchallenge"
)

type contextSMSHandler struct {
	authchallenge.UnsupportedHandler
	read func(context.Context) (string, error)
}

func (h contextSMSHandler) HandleCodeChallengeContext(ctx context.Context, ch authchallenge.CodeChallenge) (authchallenge.CodeResponse, error) {
	if ch.Kind != authchallenge.CodeSMS {
		return authchallenge.CodeResponse{}, errors.New("expected SMS")
	}
	code, err := h.read(ctx)
	return authchallenge.CodeResponse{Code: code}, err
}

func TestEasyConnectSMSPromptAndGatewayVerification(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	const legacyID = "1234567890abcdef"
	const authorizedID = "fedcba0987654321"
	var verifications atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/por/login_auth.csp":
			fmt.Fprintf(w, "<TwfID>%s</TwfID><RSA_ENCRYPT_KEY>%X</RSA_ENCRYPT_KEY><RndImg>0</RndImg>", legacyID, key.N)
		case "/por/login_psw.csp":
			fmt.Fprint(w, "<NextService>auth/sms</NextService>")
		case "/por/login_sms.csp":
			if r.Method != "POST" || r.Header.Get("Cookie") != "TWFID="+legacyID {
				t.Error("SMS request lost method or session")
			}
			fmt.Fprint(w, "<USER_PHONE>***</USER_PHONE>")
		case "/por/login_sms1.csp":
			verifications.Add(1)
			body, err := io.ReadAll(r.Body)
			form, parseErr := url.ParseQuery(string(body))
			if err != nil || parseErr != nil || form.Get("svpn_inputsms") != "012345" {
				fmt.Fprint(w, "invalid SMS token")
				return
			}
			fmt.Fprintf(w, "Auth sms suc<TwfID>%s</TwfID>", authorizedID)
		case "/por/logout.csp":
			if r.Header.Get("Cookie") != "TWFID="+authorizedID {
				t.Error("logout did not use the authorized session")
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	options := Options{
		Server: strings.TrimPrefix(server.URL, "https://"), Auth: AuthOptions{Username: "fixture", Password: "fixture"},
	}
	var output strings.Builder
	options.ChallengeHandler = authchallenge.NewCLIHandler(authchallenge.CLIOptions{
		Input: strings.NewReader("012345\n"), Output: &output,
	})
	cli := NewClient(options)
	if err := cli.ensureSession(); err != nil || cli.twfID != authorizedID || !strings.Contains(output.String(), "SMS code") {
		t.Fatalf("CLI SMS authentication failed: %v", err)
	}
	cli.Close()
	if err := cli.Logout(context.Background()); err != nil {
		t.Fatalf("logout failed: %v", err)
	}

	options.ChallengeHandler = contextSMSHandler{read: func(context.Context) (string, error) { return "000000", nil }}
	rejected := NewClient(options)
	defer rejected.Close()
	if err := rejected.ensureSession(); !errors.Is(err, ErrSMSRejected) {
		t.Fatalf("bad code returned %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	options.Context = ctx
	waiting := make(chan struct{})
	options.ChallengeHandler = contextSMSHandler{read: func(ctx context.Context) (string, error) {
		close(waiting)
		<-ctx.Done()
		return "", ctx.Err()
	}}
	managed := NewClient(options)
	defer managed.Close()
	result := make(chan error, 1)
	go func() { result <- managed.ensureSession() }()
	select {
	case <-waiting:
		cancel()
	case <-time.After(time.Second):
		t.Fatal("did not receive SMS challenge")
	}
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled SMS returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SMS challenge ignored cancellation")
	}
	if verifications.Load() != 2 {
		t.Fatal("cancelled SMS challenge reached the gateway")
	}
}

func TestSessionCheckDistinguishesGatewayExpiry(t *testing.T) {
	for _, tt := range []struct {
		name string
		code int
		body string
		loc  string
		want error
	}{
		{"active", 200, "<Auth><Message>success</Message><ErrorCode>1</ErrorCode></Auth>", "", nil},
		{"expired reply", 200, "<Auth><Message>session expired</Message><ErrorCode>0</ErrorCode></Auth>", "", ErrSessionExpired},
		{"unauthorized", 401, "", "", ErrSessionExpired},
		{"redirect", 302, "", "/por/login_auth.csp", ErrSessionExpired},
		{"older gateway", 404, "", "", errNotFound},
		{"maintenance", 503, "", "", errors.New("transient")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.loc != "" {
					w.Header().Set("Location", tt.loc)
				}
				w.WriteHeader(tt.code)
				fmt.Fprint(w, tt.body)
			}))
			defer upstream.Close()
			c := NewClient(Options{Server: strings.TrimPrefix(upstream.URL, "https://"), SessionID: "fixture"})
			defer c.Close()
			err := c.requestUpdateSession(context.Background())
			if tt.name == "maintenance" {
				if err == nil || errors.Is(err, ErrSessionExpired) {
					t.Fatalf("maintenance returned %v", err)
				}
				return
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
		})
	}
}
