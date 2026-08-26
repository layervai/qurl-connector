package config

import (
	"strings"
	"testing"
)

func TestParseTarget(t *testing.T) {
	tests := []struct {
		name         string
		raw          string
		wantType     RouteType
		wantHost     string
		wantPort     int
		wantErrMatch string // non-empty => expect error containing this substring
	}{
		{
			name:     "http default port",
			raw:      "http://localhost",
			wantType: RouteTypeHTTP,
			wantHost: "localhost",
			wantPort: 80,
		},
		{
			name:     "http explicit port",
			raw:      "http://localhost:8080",
			wantType: RouteTypeHTTP,
			wantHost: "localhost",
			wantPort: 8080,
		},
		{
			name:     "https default port",
			raw:      "https://example.internal",
			wantType: RouteTypeHTTP,
			wantHost: "example.internal",
			wantPort: 443,
		},
		{
			name:     "tcp explicit port",
			raw:      "tcp://10.0.0.5:5432",
			wantType: RouteTypeTCP,
			wantHost: "10.0.0.5",
			wantPort: 5432,
		},
		{
			name:         "tcp without port rejected",
			raw:          "tcp://localhost",
			wantErrMatch: "tcp:// target requires an explicit port",
		},
		{
			name:         "ssh rejected default port hint",
			raw:          "ssh://bastion",
			wantErrMatch: "use tcp://bastion:22 instead",
		},
		{
			name:         "ssh rejected preserves user port",
			raw:          "ssh://bastion:2222",
			wantErrMatch: "use tcp://bastion:2222 instead",
		},
		{
			name:         "ssh rejected ipv6 host keeps brackets",
			raw:          "ssh://[::1]:22",
			wantErrMatch: "use tcp://[::1]:22 instead",
		},
		{
			name:         "ssh rejected ipv6 default port keeps brackets",
			raw:          "ssh://[fe80::1]",
			wantErrMatch: "use tcp://[fe80::1]:22 instead",
		},
		{
			name:         "unknown scheme rejected",
			raw:          "udp://localhost:5000",
			wantErrMatch: `unsupported scheme "udp"`,
		},
		{
			name:         "out-of-range port rejected",
			raw:          "http://localhost:99999",
			wantErrMatch: "invalid port",
		},
		{
			// url.Parse catches trailing-garbage ports upstream, so the
			// error is wrapped as "invalid target URL". This documents
			// that strconv.Atoi in ParseTarget is a defense in depth —
			// the real gate is in the stdlib.
			name:         "trailing garbage port rejected upstream",
			raw:          "http://localhost:8080abc",
			wantErrMatch: "invalid target URL",
		},
		{
			// Port 0 slips past url.Parse as a syntactically valid port
			// but is nonsensical for a tunnel target. Exercises the local
			// `n <= 0` guard that strconv.Atoi now feeds.
			name:         "port zero rejected",
			raw:          "tcp://host:0",
			wantErrMatch: `invalid port "0"`,
		},
		{
			name:     "empty host defaults to loopback",
			raw:      "http://:8080",
			wantType: RouteTypeHTTP,
			wantHost: "127.0.0.1",
			wantPort: 8080,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rt, host, port, url, err := ParseTarget(tc.raw)
			if tc.wantErrMatch != "" {
				if err == nil {
					t.Fatalf("ParseTarget(%q) = nil error; want error containing %q", tc.raw, tc.wantErrMatch)
				}
				if !strings.Contains(err.Error(), tc.wantErrMatch) {
					t.Fatalf("ParseTarget(%q) error = %q; want substring %q", tc.raw, err.Error(), tc.wantErrMatch)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTarget(%q) unexpected error: %v", tc.raw, err)
			}
			if rt != tc.wantType {
				t.Errorf("route type = %q, want %q", rt, tc.wantType)
			}
			if host != tc.wantHost {
				t.Errorf("host = %q, want %q", host, tc.wantHost)
			}
			if port != tc.wantPort {
				t.Errorf("port = %d, want %d", port, tc.wantPort)
			}
			if url != tc.raw {
				t.Errorf("targetURL = %q, want %q (should echo input)", url, tc.raw)
			}
		})
	}
}
