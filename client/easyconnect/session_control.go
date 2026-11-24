package easyconnect

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

func (c *Client) sessionRequest(req *http.Request) (*http.Response, error) {
	client := *c.httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return client.Do(req)
}

func (c *Client) isSessionExpiryResponse(resp *http.Response) bool {
	if resp.StatusCode == http.StatusUnauthorized {
		return true
	}
	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return false
	}
	location, err := resp.Location()
	return err == nil && strings.EqualFold(location.Host, c.server) && strings.HasPrefix(location.Path, "/por/login")
}

// Logout requests server-side invalidation. The caller supplies a separate,
// bounded context so that it can log out after stopping the tunnel.
func (c *Client) Logout(ctx context.Context) error {
	if c.twfID == "" {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+c.server+"/por/logout.csp", nil)
	if err != nil {
		return errors.New("create EasyConnect logout request")
	}
	req.Header.Set("Cookie", "TWFID="+c.twfID)
	req.Header.Set("User-Agent", "EasyConnect_Linux_Ubuntu")
	defer c.httpClient.CloseIdleConnections()
	resp, err := c.sessionRequest(req)
	if err != nil {
		return errors.New("EasyConnect logout request failed")
	}
	defer resp.Body.Close()
	if (resp.StatusCode >= 200 && resp.StatusCode < 300) || c.isSessionExpiryResponse(resp) {
		return nil
	}
	return fmt.Errorf("EasyConnect logout returned HTTP %d", resp.StatusCode)
}
