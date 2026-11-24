package management

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const testBearer = "management-test-secret-do-not-log"

func managementRequest(handler http.Handler, method, path, body, bearer, origin string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "http://127.0.0.1:11083"+path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	result := httptest.NewRecorder()
	handler.ServeHTTP(result, req)
	return result
}

func TestHTTPAuthenticationAndEmbeddedPage(t *testing.T) {
	c := NewController(Options{})
	defer c.Close()
	h := NewHTTPHandler(c, HTTPOptions{Token: testBearer, WebUI: true})
	for _, path := range []string{"/api/status", "/api/health", "/api/info", "/api/logs", "/api/login", "/api/reconnect", "/api/logout", "/api/sms", "/api/cancel"} {
		res := managementRequest(h, "GET", path, "", "", "")
		if res.Code != 401 {
			t.Errorf("unauthenticated %s returned %d", path, res.Code)
		}
	}
	res := managementRequest(h, "POST", "/api/login", "{}", testBearer, "https://evil.example")
	if res.Code != 403 {
		t.Fatalf("cross-origin mutation returned %d", res.Code)
	}
	res = managementRequest(h, "GET", "/", "", "", "")
	if res.Code != 200 || !strings.Contains(res.Body.String(), `<title>xmut-connect</title>`) ||
		strings.Contains(res.Body.String(), testBearer) || res.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("expected public sign-in shell with CSP and no token")
	}
	res = managementRequest(h, "GET", "/api/health", "", testBearer, "")
	if res.Code != 503 {
		t.Fatalf("disconnected health returned %d", res.Code)
	}
	res = managementRequest(h, "GET", "/api/login", "", testBearer, "")
	if res.Code != 405 {
		t.Fatalf("GET for a mutation returned %d", res.Code)
	}
}

func TestConcurrentAPILoginSMSAndRedaction(t *testing.T) {
	gatewayError := errors.New("sensitive gateway details; 789012")
	c := NewController(Options{
		Authenticate: func(ctx context.Context, sms func(context.Context) (string, error), _ func()) (Session, error) {
			code, err := sms(ctx)
			if err != nil {
				return nil, err
			}
			if code != "789012" {
				return nil, gatewayError
			}
			return nil, errors.Join(ErrSMSRejected, gatewayError)
		},
	})
	defer c.Close()
	h := NewHTTPHandler(c, HTTPOptions{Token: testBearer})
	var wg sync.WaitGroup
	results := make(chan int, 16)
	for i := 0; i < cap(results); i++ {
		wg.Go(func() {
			res := managementRequest(h, "POST", "/api/login", "{}", testBearer, "")
			results <- res.Code
		})
	}
	wg.Wait()
	close(results)
	var accepted int
	for code := range results {
		switch code {
		case 202:
			accepted++
		case 409:
		default:
			t.Errorf("unexpected login response %d", code)
		}
	}
	if accepted != 1 {
		t.Fatalf("accepted %d concurrent logins", accepted)
	}
	waiting := waitState(t, c, WaitingSMS)
	input := `{"challenge_id":"` + waiting.ChallengeID + `","code":"789012"}`
	res := managementRequest(h, "POST", "/api/sms", input, testBearer, "")
	if res.Code != 202 {
		t.Fatal(res.Code, res.Body.String())
	}
	res = managementRequest(h, "POST", "/api/sms", input, testBearer, "")
	if res.Code != 409 {
		t.Fatalf("duplicate SMS submission returned %d", res.Code)
	}
	if got := waitState(t, c, Failed).Error; got != "sms_rejected" {
		t.Fatalf("expected stable SMS rejection code, got %q", got)
	}
	for _, path := range []string{"/api/status", "/api/logs", "/api/info", "/api/health"} {
		res := managementRequest(h, "GET", path, "", testBearer, "")
		for _, secret := range []string{testBearer, "789012", "sensitive gateway details", waiting.ChallengeID} {
			if strings.Contains(res.Body.String(), secret) {
				t.Fatalf("sensitive data in %s", path)
			}
		}
	}
}
