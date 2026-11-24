//go:build !tun

package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/mythologyli/zju-connect/internal/management"
)

func TestManagedProbeReportsHTTPStatus(t *testing.T) {
	for _, code := range []int{200, 302, 403, 404, 503} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(code)
			}))
			defer server.Close()

			tunnel := &managedTunnel{probe: server.Client(), resourceURL: server.URL}
			var wantErr error
			if code >= 400 {
				wantErr = management.ErrProbeResponse
			}
			got, err := tunnel.Probe(t.Context())
			if got != code || !errors.Is(err, wantErr) {
				t.Fatalf("Probe returned (%d, %v), want (%d, %v)", got, err, code, wantErr)
			}
		})
	}
}
