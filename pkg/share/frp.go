package share

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	v1 "github.com/fatedier/frp/pkg/config/v1"

	nhpconfig "github.com/layervai/qurl-connector/pkg/config"
)

// LocalHTTPRoute is the exact local and platform identity of one managed HTTP
// share. Public ResourceID is authorization metadata; ConnectorRoutingID is
// the stable subdomain/load-balancer identity.
type LocalHTTPRoute struct {
	RouteID            string
	LocalIP            string
	LocalPort          int
	ResourceID         string
	ConnectorRoutingID string
}

func validateLocalHTTPRoute(route LocalHTTPRoute) error {
	if route.RouteID == "" || route.ResourceID == "" || route.ConnectorRoutingID == "" {
		return errors.New("route identities are incomplete")
	}
	if route.LocalIP == "" || route.LocalPort < 1 || route.LocalPort > 65535 {
		return errors.New("local target is invalid")
	}
	return nil
}

// buildAdmittedCommon renders the Login half of one admission: the admitted
// server endpoint, the bearer knock token, and fail-fast login. The caller's
// base config is never mutated.
func buildAdmittedCommon(base *v1.ClientCommonConfig, admission Admission, clientVersion string) (*v1.ClientCommonConfig, error) {
	common := cloneCommon(base)
	host, port, err := parseAdmittedResourceHost(admission.ResourceHost)
	if err != nil {
		return nil, fmt.Errorf("parse admitted FRP host: %w", err)
	}
	if tlsEnabled(common) && common.Transport.TLS.ServerName == "" && ipLiteralHost(host) {
		return nil, errors.New("parse admitted FRP host: IP-literal target requires an explicit TLS server name")
	}
	common.ServerAddr = host
	common.ServerPort = port
	if common.Metadatas == nil {
		common.Metadatas = map[string]string{}
	}
	common.Metadatas[nhpconfig.MetaQURLKnockToken] = admission.Token
	if clientVersion != "" {
		common.Metadatas[nhpconfig.MetaClientVersion] = clientVersion
	}
	failFast := true
	common.LoginFailExit = &failFast
	return common, nil
}

// sessionProxyDiscriminator is the per-admission discriminator folded
// into every proxy name so overlapping cycles never collide on the server.
func sessionProxyDiscriminator(sessionID uint64) string {
	return "nhp" + strconv.FormatUint(sessionID, 36)
}

// buildRouteProxy renders one HTTP proxy. Group, group key, subdomain, public
// resource metadata, and the local target are the route's stable identity;
// only the name changes between cycles.
func buildRouteProxy(route LocalHTTPRoute, proxyName string) *v1.HTTPProxyConfig {
	proxy := &v1.HTTPProxyConfig{}
	proxy.Name = proxyName
	proxy.Type = string(v1.ProxyTypeHTTP)
	proxy.LocalIP = route.LocalIP
	proxy.LocalPort = route.LocalPort
	proxy.SubDomain = route.ConnectorRoutingID
	proxy.LoadBalancer.Group = route.ConnectorRoutingID
	proxy.LoadBalancer.GroupKey = route.ConnectorRoutingID
	proxy.Metadatas = map[string]string{nhpconfig.MetaResourceID: route.ResourceID}
	return proxy
}

type frpService interface {
	Run(context.Context) error
	GracefulClose(time.Duration)
}

// ErrAdmissionStale reports a qRTS rejection that requires a fresh
// resource-bound NHP admission rather than FRP's same-session retry.
var ErrAdmissionStale = errors.New("qURL share admission is no longer usable")

func proxyStartErrorTag(value string) string {
	if strings.TrimSpace(value) != value {
		return ""
	}
	tag, detail, ok := strings.Cut(value, ": ")
	if !ok || tag == "" || detail == "" {
		return ""
	}
	for _, ch := range tag {
		if (ch < 'a' || ch > 'z') && ch != '_' {
			return ""
		}
	}
	return tag
}

func cloneCommon(in *v1.ClientCommonConfig) *v1.ClientCommonConfig {
	out := *in
	if in.Metadatas != nil {
		out.Metadatas = make(map[string]string, len(in.Metadatas))
		for key, value := range in.Metadatas {
			out.Metadatas[key] = value
		}
	}
	return &out
}

// parseAdmittedResourceHost accepts only canonical host:port values. A bare
// host, ambiguous unbracketed IPv6 literal, empty host, or invalid port cannot
// fall back to a static FRP endpoint after admission.
func parseAdmittedResourceHost(value string) (string, int, error) {
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return "", 0, fmt.Errorf("split host and port: %w", err)
	}
	if strings.TrimSpace(host) == "" {
		return "", 0, errors.New("host is empty")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("port %q is outside 1..65535", portText)
	}
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		host = "[" + host + "]"
	}
	return host, port, nil
}

func ipLiteralHost(host string) bool {
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	return net.ParseIP(host) != nil
}

// tlsEnabled mirrors the audited FRP connector transport decision for the
// pinned fork. Any future protocol addition must be classified before the FRP
// dependency is advanced.
func tlsEnabled(common *v1.ClientCommonConfig) bool {
	if common == nil {
		return false
	}
	if common.Transport.TLS.Enable != nil && *common.Transport.TLS.Enable {
		return true
	}
	switch common.Transport.Protocol {
	case "wss", "quic":
		return true
	default:
		return false
	}
}
