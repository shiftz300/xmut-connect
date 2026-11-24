package management

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

// Webhook uses a bounded queue so a slow receiver cannot hold up authentication.
func Webhook(ctx context.Context, address string) func(Event) {
	if address == "" {
		return nil
	}
	queue := make(chan Event, 16)
	client := &http.Client{
		Transport: &http.Transport{},
		Timeout:   5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	go func() {
		defer client.CloseIdleConnections()
		for {
			select {
			case <-ctx.Done():
				return
			case event := <-queue:
				data, _ := json.Marshal(event)
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, address, bytes.NewReader(data))
				if err != nil {
					logger.Print("WARN webhook_failed")
					continue
				}
				req.Header.Set("Content-Type", "application/json")
				resp, err := client.Do(req)
				if err != nil {
					if ctx.Err() == nil {
						logger.Print("WARN webhook_failed")
					}
					continue
				}
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
				_ = resp.Body.Close()
				if resp.StatusCode < 200 || resp.StatusCode >= 300 {
					logger.Print("WARN webhook_rejected")
				}
			}
		}
	}()
	return func(e Event) {
		select {
		case queue <- e:
		default:
			logger.Print("WARN webhook_queue_full")
		}
	}
}
