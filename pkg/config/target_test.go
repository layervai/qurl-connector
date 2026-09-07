package config

import (
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
		{raw: "https://example.com", wantHost: "example.com", wantPort: 443},
		{raw: "http://127.0.0.1:8080", wantHost: "127.0.0.1", wantPort: 8080},
		{raw: "https://[::1]:8443", wantHost: "::1", wantPort: 8443},
		{raw: "http://:8080", wantHost: "127.0.0.1", wantPort: 8080},
		{raw: "tcp://localhost:22", wantError: "use http:// or https://"},
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
