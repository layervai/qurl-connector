package config

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// ParseTarget parses a managed HTTP target. Empty hostname defaults to
// 127.0.0.1.
//
// Schemes:
//   - http  -> default port 80
//   - https -> default port 443
func ParseTarget(raw string) (host string, port int, targetURL string, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", 0, "", fmt.Errorf("invalid target URL: %w", err)
	}

	scheme := strings.ToLower(u.Scheme)
	host = u.Hostname()
	if host == "" {
		host = "127.0.0.1"
	}

	portStr := u.Port()

	switch scheme {
	case "http":
		if portStr == "" {
			port = 80
		}
	case "https":
		if portStr == "" {
			port = 443
		}
	default:
		return "", 0, "", fmt.Errorf("unsupported scheme %q (use http:// or https://)", scheme)
	}

	if port == 0 {
		// strconv.Atoi (vs fmt.Sscanf "%d") rejects trailing garbage —
		// "123abc" must fail, not parse as 123.
		n, err := strconv.Atoi(portStr)
		if err != nil || n <= 0 || n > 65535 {
			return "", 0, "", fmt.Errorf("invalid port %q", portStr)
		}
		port = n
	}

	return host, port, raw, nil
}
