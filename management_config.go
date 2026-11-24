package main

import (
	"errors"
	"net"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/mythologyli/zju-connect/configs"
)

func checkManagementConfigFile(path string) error {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("management requires a regular config file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return errors.New("management config file must be private (chmod 600)")
	}
	return nil
}

func parseManagementURL(value string, httpsOnly bool) (*url.URL, bool) {
	parsed, err := url.Parse(value)
	return parsed, err == nil && parsed.Hostname() != "" &&
		(parsed.Scheme == "https" || (!httpsOnly && parsed.Scheme == "http")) &&
		parsed.User == nil && parsed.Fragment == ""
}

func validLoopbackBind(value string) bool {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	n, err := strconv.Atoi(port)
	return ip != nil && ip.IsLoopback() && err == nil && n > 0 && n <= 65535
}

func validateManagementConfig(cfg *configs.Config) error {
	if cfg.Protocol != "easyconnect" || cfg.TUNMode || cfg.DNSHijack || cfg.AddRoute ||
		cfg.FakeIP || cfg.DNSServerBind != "" || len(cfg.PortForwardingList) != 0 {
		return errors.New("management supports EasyConnect in proxy mode (Shadowsocks, SOCKS5 and HTTP)")
	}
	if cfg.Username == "" || cfg.Password == "" || cfg.TwfID != "" || cfg.DisableServerConfig {
		return errors.New("management requires VPN username, password and server resources")
	}
	if cfg.DebugDump || cfg.DebugPCAPFile != "" || cfg.DebugTLSLogFile != "" {
		return errors.New("management requires protocol dumps and TLS key logging to be disabled")
	}
	if !validLoopbackBind(cfg.ManagementBind) {
		return errors.New("management_bind must be a loopback IP address and port")
	}
	if n := len(cfg.ManagementToken); n < 32 || n > 256 || strings.IndexFunc(cfg.ManagementToken, func(r rune) bool {
		return r < '!' || r > '~' || r == ','
	}) >= 0 {
		return errors.New("management_token must contain 32 to 256 printable ASCII characters without spaces or commas")
	}
	if cfg.ManagementOrigin != "" {
		origin, ok := parseManagementURL(cfg.ManagementOrigin, true)
		if !ok || cfg.ManagementOrigin != origin.Scheme+"://"+origin.Host {
			return errors.New("management_origin must be an HTTPS origin without a path")
		}
	}
	if _, ok := parseManagementURL(cfg.HealthCheckURL, false); !ok {
		return errors.New("health_check_url must point to an HTTP(S) campus resource")
	}
	if cfg.HealthInterval < 5 || cfg.HealthInterval > 3600 || cfg.SMSWaitTimeout < 10 || cfg.SMSWaitTimeout > 600 {
		return errors.New("health_check_interval must be 5–3600 seconds and sms_wait_timeout 10–600 seconds")
	}
	if cfg.WebhookURL != "" {
		if _, ok := parseManagementURL(cfg.WebhookURL, true); !ok {
			return errors.New("webhook_url must be an HTTPS URL")
		}
	}
	for _, bind := range []*string{&cfg.SocksBind, &cfg.HTTPBind} {
		if *bind == "" {
			continue
		}
		if strings.HasPrefix(*bind, ":") {
			*bind = "127.0.0.1" + *bind
		}
		if !validLoopbackBind(*bind) {
			return errors.New("management requires SOCKS5 and HTTP proxies to use loopback bind addresses")
		}
	}
	if cfg.ShadowsocksURL != "" {
		u, err := url.Parse(cfg.ShadowsocksURL)
		if err != nil || u.Scheme != "ss" || u.Host == "" || u.User == nil ||
			u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("invalid shadowsocks_url")
		}
		switch strings.ToLower(u.User.Username()) {
		case "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "aead_aes_128_gcm", "aead_aes_256_gcm", "aead_chacha20_poly1305":
		default:
			return errors.New("management requires a supported Shadowsocks AEAD cipher")
		}
		port, err := strconv.Atoi(u.Port())
		password, _ := u.User.Password()
		if err != nil || port < 1 || port > 65535 || len(password) < 16 {
			return errors.New("Shadowsocks requires a valid port and a password of at least 16 bytes")
		}
	}
	return nil
}
