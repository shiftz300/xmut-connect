package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/mythologyli/zju-connect/configs"
)

func TestManagementConfigPrecedenceAndPrivateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	data := []byte(`management_enabled = true
management_token = "sample-only-0123456789abcdef0123456789"
health_check_url = "https://campus.example/health"
health_check_interval = 7
username = "fixture"
password = "fixture"
`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	env := func() []string {
		return []string{"ZJU_CONNECT_CONFIG=" + path, "ZJU_CONNECT_HEALTH_CHECK_INTERVAL=11"}
	}
	args := []string{"-health-check-interval=13"}
	startup, _, err := loadStartupOptions(args, env)
	if err != nil {
		t.Fatal(err)
	}
	cfg := startup.Config
	if err := validateManagementConfig(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.ManagementBind != "127.0.0.1:11083" || !cfg.ManagementWebUI || cfg.HealthInterval != 13 ||
		cfg.SocksBind != "127.0.0.1:1080" || cfg.HTTPBind != "127.0.0.1:1081" {
		t.Fatalf("incorrect resolved management settings")
	}
	if runtime.GOOS == "windows" {
		return
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	_, _, err = loadStartupOptions(args, env)
	if err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("insecure config file returned %v", err)
	}
	if _, _, err := loadStartupOptions([]string{"-management-enabled=false"}, env); err != nil {
		t.Fatalf("original CLI mode could not load standard config: %v", err)
	}
}

func TestManagementRejectsInsecureSettings(t *testing.T) {
	for name, change := range map[string]func(*configs.Config){
		"wildcard management": func(cfg *configs.Config) { cfg.ManagementBind = "0.0.0.0:11083" },
		"cleartext webhook":   func(cfg *configs.Config) { cfg.WebhookURL = "http://localhost/a" },
		"invalid origin":      func(cfg *configs.Config) { cfg.ManagementOrigin = "https://example.com/" },
		"invalid health URL":  func(cfg *configs.Config) { cfg.HealthCheckURL = "ftp://example.com/" },
		"unauthenticated SS":  func(cfg *configs.Config) { cfg.ShadowsocksURL = "ss://DUMMY@:1082" },
		"wildcard SOCKS":      func(cfg *configs.Config) { cfg.SocksBind = "0.0.0.0:1080" },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := configs.Default()
			cfg.ManagementEnabled = true
			cfg.ManagementToken = strings.Repeat("x", 40)
			cfg.HealthCheckURL = "https://campus.example/health"
			cfg.Username, cfg.Password = "fixture", "fixture"
			change(&cfg)
			if err := validateManagementConfig(&cfg); err == nil {
				t.Fatal("expected invalid configuration")
			}
		})
	}
}

func TestManagementTokenLength(t *testing.T) {
	cfg := configs.Default()
	cfg.ManagementEnabled = true
	cfg.Username, cfg.Password = "fixture", "fixture"
	// Management can start with the default empty health check URL.
	for _, size := range []int{7, 8, 64, 256, 257} {
		cfg.ManagementToken = strings.Repeat("x", size)
		err := validateManagementConfig(&cfg)
		if wantError := size < 8 || size > 256; (err != nil) != wantError {
			t.Errorf("management token length %d returned %v, want error %t", size, err, wantError)
		}
	}
}
