package management

import (
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"time"
)

//go:embed web/*
var webFiles embed.FS

type HTTPOptions struct {
	Token, Origin string
	WebUI         bool
}

type requestLimit struct {
	mu        sync.Mutex
	start     time.Time
	count     int
	perMinute int
}

func (l *requestLimit) allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if now.Sub(l.start) >= time.Minute {
		l.start, l.count = now, 0
	}
	l.count++
	return l.count <= l.perMinute
}

func NewHTTPHandler(c *Controller, opts HTTPOptions) http.Handler {
	api := http.NewServeMux()
	start := time.Now()
	api.HandleFunc("GET /api/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, c.Status())
	})
	api.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		health := c.Status().Health
		code := http.StatusServiceUnavailable
		if health.Status == "healthy" {
			code = http.StatusOK
		}
		writeJSON(w, code, health)
	})
	api.HandleFunc("GET /api/info", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"version": c.options.Version, "protocol": "easyconnect", "os": runtime.GOOS,
			"arch": runtime.GOARCH, "started_at": start,
		})
	})
	api.HandleFunc("GET /api/logs", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, c.events.list())
	})

	action := func(fn func() error) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) { writeAction(w, fn()) }
	}
	api.HandleFunc("POST /api/login", action(c.Login))
	api.HandleFunc("POST /api/reconnect", action(c.Reconnect))
	api.HandleFunc("POST /api/logout", action(c.Logout))
	api.HandleFunc("POST /api/cancel", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			AttemptID string `json:"attempt_id"`
		}
		if readJSON(w, r, &input) {
			writeAction(w, c.Cancel(input.AttemptID))
		}
	})
	api.HandleFunc("POST /api/sms", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			ChallengeID string `json:"challenge_id"`
			Code        string `json:"code"`
		}
		if !readJSON(w, r, &input) {
			return
		}
		if !validCode(input.Code) {
			writeError(w, http.StatusBadRequest, "invalid_sms_code")
			return
		}
		writeAction(w, c.SubmitSMS(input.ChallengeID, input.Code))
	})

	webRoot, _ := fs.Sub(webFiles, "web")
	ui := http.FileServer(http.FS(webRoot))
	token := sha256.Sum256([]byte(opts.Token))
	reads := requestLimit{perMinute: 240}
	writes := requestLimit{perMinute: 40}
	origin, _ := url.Parse(opts.Origin)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'")

		host := r.Host
		if value, _, err := net.SplitHostPort(host); err == nil {
			host = value
		}
		ip := net.ParseIP(strings.Trim(host, "[]"))
		local := strings.EqualFold(host, "localhost") || (ip != nil && ip.IsLoopback())
		external := opts.Origin != "" && origin != nil && strings.EqualFold(origin.Host, r.Host)
		if !local && !external {
			writeError(w, http.StatusForbidden, "invalid_host")
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			switch r.URL.Path {
			case "/", "/style.css", "/app.js":
				if opts.WebUI && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
					ui.ServeHTTP(w, r)
					return
				}
			}
			writeError(w, http.StatusNotFound, "not_found")
			return
		}

		if site := r.Header.Get("Sec-Fetch-Site"); site == "cross-site" || site == "same-site" {
			writeError(w, http.StatusForbidden, "cross_origin")
			return
		}
		if value := r.Header.Get("Origin"); value != "" {
			trustedOrigin := "http://" + r.Host
			if external {
				trustedOrigin = opts.Origin
			}
			if value != trustedOrigin {
				writeError(w, http.StatusForbidden, "cross_origin")
				return
			}
		}

		provided, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		given := sha256.Sum256([]byte(provided))
		if !ok || opts.Token == "" || subtle.ConstantTimeCompare(token[:], given[:]) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="VPN management"`)
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		limit := &reads
		if r.Method != http.MethodGet {
			limit = &writes
		}
		if !limit.allow() {
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests, "request_rate_limited")
			return
		}
		if _, pattern := api.Handler(r); pattern == "" {
			if r.URL.Path == "/api/status" || r.URL.Path == "/api/health" ||
				r.URL.Path == "/api/info" || r.URL.Path == "/api/logs" ||
				r.URL.Path == "/api/login" || r.URL.Path == "/api/reconnect" ||
				r.URL.Path == "/api/logout" || r.URL.Path == "/api/cancel" || r.URL.Path == "/api/sms" {
				writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
			} else {
				writeError(w, http.StatusNotFound, "not_found")
			}
			return
		}
		api.ServeHTTP(w, r)
	})
}

func validCode(code string) bool {
	if len(code) == 0 || len(code) > 12 {
		return false
	}
	for _, ch := range code {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

func readJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaType != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "json_required")
		return false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil || decoder.Decode(new(any)) != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return false
	}
	return true
}

func writeAction(w http.ResponseWriter, err error) {
	switch {
	case err == nil:
		writeJSON(w, http.StatusAccepted, map[string]bool{"accepted": true})
	case errors.Is(err, ErrCooldown):
		w.Header().Set("Retry-After", "15")
		writeError(w, http.StatusTooManyRequests, ErrCooldown.Error())
	default:
		writeError(w, http.StatusConflict, err.Error())
	}
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
