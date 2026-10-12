package share

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"golang.org/x/net/http/httpguts"

	nhpconfig "github.com/layervai/qurl-connector/pkg/config"
)

// Unix sockaddr paths have a 104-byte ceiling on macOS; leave room for the NUL.
const maxLocalSocketPathBytes = 100

// LocalHTTPRoute is the exact local and platform identity of one managed HTTP
// share. Public ResourcePublicKey is authorization metadata; ConnectorRoutingID is
// the stable subdomain/load-balancer identity.
//
// The route holds a map, so it is not comparable with ==: compare
// registrations with Equal and header sets alone with RequestHeadersDigest.
// Its formatting methods redact the request headers and JSON/YAML encoding
// omits them.
type LocalHTTPRoute struct {
	RouteID   string
	LocalIP   string
	LocalPort int
	// LocalSocketPath selects a private Unix HTTP origin instead of TCP.
	// It is runtime-only: JSON/YAML and formatting omit the pathname, so
	// callers must restore it before loading a serialized route. The local
	// supervisor must provide an owner-only socket directory whose ancestors
	// untrusted principals cannot replace, and owns the listener lifetime;
	// this library validates syntax and never unlinks or replaces the socket.
	LocalSocketPath string `json:"-" yaml:"-"`
	// LocalPipeName selects a private Windows named-pipe HTTP origin instead
	// of TCP, in the canonical form ValidateLocalPipeName accepts. It is
	// runtime-only like LocalSocketPath. Every dial checks that the connected
	// pipe is owned by this process's user and refuses it otherwise. Where
	// the "Default owner for objects created by members of the Administrators
	// group" policy is set to Administrators, an elevated producer's pipe is
	// owned by BUILTIN\Administrators and every request to it fails closed.
	// The owner check does not restrict who else may open the producer's pipe;
	// the producer owns that DACL (the default pipe DACL grants Everyone read).
	LocalPipeName      string `json:"-" yaml:"-"`
	ResourcePublicKey  string
	ConnectorRoutingID string
	// RequestHeaders are runtime-only values sent to frps in NewProxy and
	// applied to requests reaching the local origin. They are never
	// persisted or logged, and are returned to the owning caller only as a
	// copy through RouteStates; the map is cloned on the way in and
	// per rendered cycle. A non-empty map requires an encrypted FRP
	// transport with certificate verification enabled and the local FRP
	// web/admin server disabled. At most 16 entries and 1,024 aggregate name
	// and value bytes. An empty value is
	// allowed (a marker header) and still counts as an entry.
	RequestHeaders map[string]string `json:"-" yaml:"-"`
}

// String keeps runtime request-header names and values out of logs,
// assertions, and diagnostics.
func (r LocalHTTPRoute) String() string {
	privateOrigin := ""
	if r.LocalSocketPath != "" {
		privateOrigin += ", LocalSocketPath:[REDACTED]"
	}
	if r.LocalPipeName != "" {
		privateOrigin += ", LocalPipeName:[REDACTED]"
	}
	return fmt.Sprintf(
		"share.LocalHTTPRoute{RouteID:%q, LocalIP:%q, LocalPort:%d, ResourcePublicKey:%q, ConnectorRoutingID:%q%s, RequestHeaders:[REDACTED]}",
		r.RouteID, r.LocalIP, r.LocalPort, r.ResourcePublicKey, r.ConnectorRoutingID, privateOrigin,
	)
}

// GoString applies the same redaction to %#v formatting.
func (r LocalHTTPRoute) GoString() string { return r.String() }

func (r LocalHTTPRoute) hasRequestHeaders() bool { return len(r.RequestHeaders) > 0 }
func (r LocalHTTPRoute) hasPrivateOrigin() bool {
	return r.LocalSocketPath != "" || r.LocalPipeName != ""
}

// Equal reports whether two routes are the same registration: identity,
// local target, and runtime request headers all match (nil and empty
// headers are both headerless). TestLocalHTTPRouteEqualCoversEveryField
// keeps it in step with the fields.
func (r LocalHTTPRoute) Equal(other LocalHTTPRoute) bool {
	return r.RouteID == other.RouteID && r.LocalIP == other.LocalIP && r.LocalPort == other.LocalPort && r.LocalSocketPath == other.LocalSocketPath && r.LocalPipeName == other.LocalPipeName &&
		r.ResourcePublicKey == other.ResourcePublicKey && r.ConnectorRoutingID == other.ConnectorRoutingID &&
		maps.Equal(r.RequestHeaders, other.RequestHeaders)
}

func validateLocalHTTPRoute(route LocalHTTPRoute) error {
	if route.RouteID == "" || route.ResourcePublicKey == "" || route.ConnectorRoutingID == "" {
		return errors.New("route identities are incomplete")
	}
	if route.LocalPipeName != "" {
		if route.LocalIP != "" || route.LocalPort != 0 || route.LocalSocketPath != "" {
			return errors.New("local named-pipe target is invalid")
		}
		if err := ValidateLocalPipeName(route.LocalPipeName); err != nil {
			return err
		}
	} else if route.LocalSocketPath != "" {
		if runtime.GOOS == "windows" || route.LocalIP != "" || route.LocalPort != 0 ||
			!filepath.IsAbs(route.LocalSocketPath) || filepath.Clean(route.LocalSocketPath) != route.LocalSocketPath ||
			len(route.LocalSocketPath) > maxLocalSocketPathBytes || strings.ContainsAny(route.LocalSocketPath, "\x00\r\n") {
			return errors.New("local Unix socket target is invalid")
		}
	} else if route.LocalIP == "" || route.LocalPort < 1 || route.LocalPort > 65535 {
		return errors.New("local target is invalid")
	}
	return ValidateRequestHeaders(route.RequestHeaders)
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
// only the name changes between cycles. A headerless route leaves the
// header set nil so its NewProxy bytes are exactly what they were before
// routes could carry headers.
func buildRouteProxy(route LocalHTTPRoute, proxyName string) *v1.HTTPProxyConfig {
	proxy := &v1.HTTPProxyConfig{}
	proxy.Name = proxyName
	proxy.Type = string(v1.ProxyTypeHTTP)
	proxy.LocalIP = route.LocalIP
	proxy.LocalPort = route.LocalPort
	// validateLocalHTTPRoute rejects routes naming both; the switch keeps a
	// bypassed validator from silently letting one transport overwrite the other.
	switch {
	case route.LocalSocketPath != "" && route.LocalPipeName != "":
		// validateLocalHTTPRoute rejects this first. If bypassed, render no plugin
		// and port 0: FRP accepts it, but 127.0.0.1:0 can never be dialed.
		proxy.LocalIP, proxy.LocalPort = "", 0
	case route.LocalSocketPath != "":
		proxy.Plugin = v1.TypedClientPluginOptions{
			Type:                v1.PluginUnixDomainSocket,
			ClientPluginOptions: &v1.UnixDomainSocketPluginOptions{Type: v1.PluginUnixDomainSocket, UnixPath: route.LocalSocketPath},
		}
	case route.LocalPipeName != "":
		proxy.Plugin = v1.TypedClientPluginOptions{Type: localPipePluginName, ClientPluginOptions: &localPipeOptions{PipeName: route.LocalPipeName}}
	}
	proxy.SubDomain = route.ConnectorRoutingID
	proxy.LoadBalancer.Group = route.ConnectorRoutingID
	proxy.LoadBalancer.GroupKey = route.ConnectorRoutingID
	proxy.Metadatas = map[string]string{nhpconfig.MetaResourceID: route.ResourcePublicKey}
	proxy.RequestHeaders.Set = cloneRequestHeaders(route.RequestHeaders)
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

// cloneCommon copies the config and TLS flag pointees so a cycle keeps
// the encryption and handshake framing that were validated.
func cloneCommon(in *v1.ClientCommonConfig) *v1.ClientCommonConfig {
	out := *in
	if in.Transport.TLS.Enable != nil {
		enabled := *in.Transport.TLS.Enable
		out.Transport.TLS.Enable = &enabled
	}
	if in.Transport.TLS.DisableCustomTLSFirstByte != nil {
		disabled := *in.Transport.TLS.DisableCustomTLSFirstByte
		out.Transport.TLS.DisableCustomTLSFirstByte = &disabled
	}
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

// routeTransportError fails closed when a route set carries runtime
// request headers and the FRP transport would expose them: a plaintext
// control connection sends NewProxy in the clear, unverified TLS permits
// interception, and the local FRP
// web/admin server reports every proxy's configuration to whoever reaches
// it. Private origins also require the web/admin server disabled because proxy
// configuration includes their private pathname. Messages disclose neither.
func routeTransportError(common *v1.ClientCommonConfig, headered, privateOrigin bool) error {
	if privateOrigin && common != nil && common.WebServer.Port > 0 {
		return errors.New("private origins require FRP web server to be disabled")
	}
	if !headered {
		return nil
	}
	if !tlsEnabled(common) {
		return errors.New("runtime request headers require encrypted FRP transport")
	}
	// Explicit verification uses system roots when no private CA is supplied.
	if !common.Transport.TLS.VerifyServerCertificate &&
		(common.Transport.TLS.TrustedCaFile == "" ||
			(common.Transport.Protocol == "quic" &&
				(common.Transport.TLS.Enable == nil || !*common.Transport.TLS.Enable))) {
		return errors.New("runtime request headers require a verified FRP server certificate")
	}
	if common.WebServer.Port > 0 {
		return errors.New("runtime request headers require FRP web server to be disabled")
	}
	return nil
}

// The pinned FRP JSON reader caps a control message at 10,240 bytes.
// encoding/json can expand each raw string byte to six wire bytes, so the
// count and aggregate caps leave roughly 4 KiB for the existing envelope.
const (
	maxRuntimeRequestHeaderCount = 16
	maxRuntimeRequestHeaderBytes = 1024
)

// RequestHeadersDigest hashes the sorted, length-prefixed header entries with
// SHA-256. Nil and empty maps both return "". Treat the digest as secret:
// low-entropy values can be recovered by guessing. Never log or persist it.
// Use Equal when both routes are available.
func RequestHeadersDigest(headers map[string]string) string {
	if len(headers) == 0 {
		return ""
	}
	names := slices.Sorted(maps.Keys(headers))
	var canonical strings.Builder
	for _, name := range names {
		value := headers[name]
		canonical.WriteString(strconv.Itoa(len(name)))
		canonical.WriteByte(':')
		canonical.WriteString(strconv.Itoa(len(value)))
		canonical.WriteByte(':')
		canonical.WriteString(name)
		canonical.WriteByte('=')
		canonical.WriteString(value)
		canonical.WriteByte('\n')
	}
	sum := sha256.Sum256([]byte(canonical.String()))
	return hex.EncodeToString(sum[:])
}

// ValidateRequestHeaders checks a runtime request-header set against the
// runtime limits and HTTP's own rules: token names, valid UTF-8 values with
// no control bytes, no hop-by-hop, forwarding, or framing names, and no two
// names that differ only in case. The errors are fixed strings that never carry a
// header, and the checks run in a deterministic order so the same input
// always yields the same error. A nil or empty map is valid.
func ValidateRequestHeaders(headers map[string]string) error {
	if len(headers) > maxRuntimeRequestHeaderCount {
		return errors.New("request headers exceed runtime limits")
	}
	aggregateBytes := 0
	for name, value := range headers {
		aggregateBytes += len(name) + len(value)
	}
	if aggregateBytes > maxRuntimeRequestHeaderBytes {
		return errors.New("request headers exceed runtime limits")
	}

	names := slices.Sorted(maps.Keys(headers))
	seen := make(map[string]struct{}, len(headers))
	for _, name := range names {
		value := headers[name]
		if !httpguts.ValidHeaderFieldName(name) {
			return errors.New("request header name is invalid")
		}
		canonicalName := strings.ToLower(name)
		if reservedRequestHeaderName(canonicalName) {
			return errors.New("request header name is reserved")
		}
		if _, ok := seen[canonicalName]; ok {
			return errors.New("request header names are duplicated")
		}
		seen[canonicalName] = struct{}{}
		if !validHTTPHeaderValue(value) {
			return errors.New("request header value is invalid")
		}
	}
	return nil
}

// cloneRequestHeaders copies a header map so a caller's later mutation cannot
// reach a live cycle; a headerless map normalizes to nil.
func cloneRequestHeaders(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	return maps.Clone(in)
}

func reservedRequestHeaderName(canonicalName string) bool {
	switch canonicalName {
	case "host",
		"content-length",
		"connection",
		"proxy-connection",
		"keep-alive",
		"proxy-authenticate",
		"proxy-authorization",
		"te",
		"trailer",
		"transfer-encoding",
		"upgrade",
		"forwarded",
		"x-forwarded-for",
		"x-forwarded-host",
		"x-forwarded-proto",
		"x-real-ip",
		"x-forwarded-port":
		return true
	default:
		return false
	}
}

// validHTTPHeaderValue is Go's HTTP transport rule plus valid UTF-8: the FRP
// control channel carries the value as JSON, which would rewrite any other
// byte to U+FFFD before the origin saw it.
func validHTTPHeaderValue(value string) bool {
	return utf8.ValidString(value) && httpguts.ValidHeaderFieldValue(value)
}
