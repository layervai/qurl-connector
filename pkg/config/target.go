package config

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// ParseTarget parses a user-supplied target URL (e.g. http://localhost:8080,
// tcp://10.0.0.5:5432) and returns the corresponding FRP route type, host,
// port, and the original URL. Empty hostname defaults to 127.0.0.1.
//
// Schemes:
//   - http  -> RouteTypeHTTP, default port 80
//   - https -> RouteTypeHTTP, default port 443
//   - tcp   -> RouteTypeTCP,  explicit port required
//   - ssh   -> rejected with a hint to use tcp://host:port
func ParseTarget(raw string) (routeType RouteType, host string, port int, targetURL string, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", 0, "", fmt.Errorf("invalid target URL: %w", err)
	}

	scheme := strings.ToLower(u.Scheme)
	host = u.Hostname()
	if host == "" {
		host = "127.0.0.1"
	}

	portStr := u.Port()

	switch scheme {
	case "http":
		routeType = RouteTypeHTTP
		if portStr == "" {
			port = 80
		}
	case "https":
		routeType = RouteTypeHTTP
		if portStr == "" {
			port = 443
		}
	case "tcp":
		routeType = RouteTypeTCP
		if portStr == "" {
			return "", "", 0, "", fmt.Errorf("tcp:// target requires an explicit port")
		}
	case "ssh":
		suggestedPort := portStr
		if suggestedPort == "" {
			suggestedPort = "22"
		}
		// net.JoinHostPort wraps IPv6 literals in brackets so the hint
		// renders as tcp://[::1]:22 rather than the malformed tcp://::1:22.
		return "", "", 0, "", fmt.Errorf("ssh:// is no longer supported; use tcp://%s instead", net.JoinHostPort(host, suggestedPort))
	default:
		return "", "", 0, "", fmt.Errorf("unsupported scheme %q (use http://, https://, or tcp://)", scheme)
	}

	if port == 0 {
		// strconv.Atoi (vs fmt.Sscanf "%d") rejects trailing garbage —
		// "123abc" must fail, not parse as 123.
		n, err := strconv.Atoi(portStr)
		if err != nil || n <= 0 || n > 65535 {
			return "", "", 0, "", fmt.Errorf("invalid port %q", portStr)
		}
		port = n
	}

	return routeType, host, port, raw, nil
}
