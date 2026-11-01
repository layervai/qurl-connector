package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseTarget(t *testing.T) {
	tests := []struct {
		raw       string
		wantHost  string
		wantPort  int
		wantError string
	}{
		{raw: "http://localhost", wantHost: "localhost", wantPort: 80},
		{raw: "https://example.com", wantError: "HTTPS origins are not supported"},
		{raw: "http://127.0.0.1:8080", wantHost: "127.0.0.1", wantPort: 8080},
		{raw: "https://[::1]:8443", wantError: "HTTPS origins are not supported"},
		{raw: "http://:8080", wantHost: "127.0.0.1", wantPort: 8080},
		{raw: "tcp://localhost:22", wantError: "use http://"},
		{raw: "http://localhost:0", wantError: "invalid port"},
		{raw: "http://localhost:70000", wantError: "invalid port"},
	}
	for _, test := range tests {
		t.Run(test.raw, func(t *testing.T) {
			host, port, raw, err := ParseTarget(test.raw)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("ParseTarget(%q) error = %v, want %q", test.raw, err, test.wantError)
				}
				return
			}
			if err != nil || host != test.wantHost || port != test.wantPort || raw != test.raw {
				t.Fatalf("ParseTarget(%q) = (%q, %d, %q, %v)", test.raw, host, port, raw, err)
			}
		})
	}
}

func TestLoadKeepsLegacyTargetMetadataEditable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "qurl-proxy.yaml")
	const saved = `routes:
  - id: legacy-tls
    type: http
    local_port: 8443
    target_url: https://localhost:8443
  - id: working-http
    type: http
    local_port: 8080
    target_url: http://localhost:8080
`
	if err := os.WriteFile(path, []byte(saved), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil || len(cfg.Routes) != 2 {
		t.Fatalf("legacy metadata must not block config edits or healthy siblings: %v", err)
	}
}
