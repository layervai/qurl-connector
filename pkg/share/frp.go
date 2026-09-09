package share

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	v1 "github.com/fatedier/frp/pkg/config/v1"

	nhpconfig "github.com/layervai/qurl-connector/pkg/config"
)

// LocalHTTPRoute is the exact local and platform identity of one managed HTTP
// share. Public ResourcePublicKey is authorization metadata; ConnectorRoutingID is
// the stable subdomain/load-balancer identity.
//
// The route holds a map, so it is not comparable with ==: compare
// registrations with Equal and header sets alone with RequestHeadersDigest.
// Its formatting methods redact the request headers and JSON/YAML encoding
// omits them.
type LocalHTTPRoute struct {
	RouteID            string
	LocalIP            string
	LocalPort          int
	ResourcePublicKey  string
	ConnectorRoutingID string
	// RequestHeaders are runtime-only values sent to frps in NewProxy and
	// applied to requests reaching the local origin. They are never
	// persisted, logged, or reported; the map is cloned on the way in and
	// per rendered cycle. A non-empty map requires an encrypted FRP
	// transport and the local FRP web/admin server disabled. At most 16
	// entries and 1,024 aggregate name and value bytes. An empty value is
	// allowed (a marker header) and still counts as an entry.
	RequestHeaders map[string]string `json:"-" yaml:"-"`
}

// String keeps runtime request-header names and values out of logs,
// assertions, and diagnostics.
func (r LocalHTTPRoute) String() string {
	return fmt.Sprintf(
		"share.LocalHTTPRoute{RouteID:%q, LocalIP:%q, LocalPort:%d, ResourcePublicKey:%q, ConnectorRoutingID:%q, RequestHeaders:[REDACTED]}",
		r.RouteID, r.LocalIP, r.LocalPort, r.ResourcePublicKey, r.ConnectorRoutingID,
	)
}

// GoString applies the same redaction to %#v formatting.
func (r LocalHTTPRoute) GoString() string { return r.String() }

// Equal reports whether two routes are the same registration: identity,
// local target, and runtime request headers all match (nil and empty
// headers are both headerless). TestLocalHTTPRouteEqualCoversEveryField
// keeps it in step with the fields.
func (r LocalHTTPRoute) Equal(other LocalHTTPRoute) bool {
	return r.RouteID == other.RouteID && r.LocalIP == other.LocalIP && r.LocalPort == other.LocalPort &&
		r.ResourcePublicKey == other.ResourcePublicKey && r.ConnectorRoutingID == other.ConnectorRoutingID &&
		maps.Equal(r.RequestHeaders, other.RequestHeaders)
}

func validateLocalHTTPRoute(route LocalHTTPRoute) error {
	if route.RouteID == "" || route.ResourcePublicKey == "" || route.ConnectorRoutingID == "" {
		return errors.New("route identities are incomplete")
	}
	if route.LocalIP == "" || route.LocalPort < 1 || route.LocalPort > 65535 {
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

// cloneCommon copies the caller's config for one cycle. The TLS enablement
// pointee is copied too, so the transport a cycle was checked against is the
// transport it keeps: a caller flipping its own flag later cannot turn
// encryption off under a session that carries request headers.
func cloneCommon(in *v1.ClientCommonConfig) *v1.ClientCommonConfig {
	out := *in
	if in.Transport.TLS.Enable != nil {
		enabled := *in.Transport.TLS.Enable
		out.Transport.TLS.Enable = &enabled
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

// requestHeaderTransportError fails closed when a route set carries runtime
// request headers and the FRP transport would expose them: a plaintext
// control connection sends NewProxy in the clear, and the local FRP
// web/admin server reports every proxy's configuration to whoever reaches
// it. A headerless set is never gated. The message names no header.
func requestHeaderTransportError(common *v1.ClientCommonConfig, headered bool) error {
	if !headered {
		return nil
	}
	if !tlsEnabled(common) {
		return errors.New("runtime request headers require encrypted FRP transport")
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

// RequestHeadersDigest is a stable identity for a header set: the entries as
// sorted len(name):len(value):name=value lines, SHA-256, lowercase hex. The
// length prefixes keep the form injective whatever the entries hold, so two
// distinct sets never share a digest. A nil and an empty map are the same
// headerless set and digest to "". It lets a caller detect a change without
// keeping the values; two sets with the same digest are the same
// registration to SessionGroupRunner.SetRoutes.
func RequestHeadersDigest(headers map[string]string) string {
	if len(headers) == 0 {
		return ""
	}
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
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
// runtime limits and HTTP's own rules: token names, no control bytes in
// values, no hop-by-hop, forwarding, or framing names, and no two names that
// differ only in case. The errors are fixed strings that never carry a
// header, and the checks run in a deterministic order so the same input
// always yields the same error. A nil or empty map is valid.
func ValidateRequestHeaders(headers map[string]string) error {
	if len(headers) > maxRuntimeRequestHeaderCount {
		return errors.New("request headers exceed runtime limits")
	}
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	aggregateBytes := 0
	for _, name := range names {
		if len(name) > maxRuntimeRequestHeaderBytes-aggregateBytes {
			return errors.New("request headers exceed runtime limits")
		}
		aggregateBytes += len(name)
		if len(headers[name]) > maxRuntimeRequestHeaderBytes-aggregateBytes {
			return errors.New("request headers exceed runtime limits")
		}
		aggregateBytes += len(headers[name])
	}

	seen := make(map[string]struct{}, len(headers))
	for _, name := range names {
		value := headers[name]
		if !validHTTPHeaderName(name) {
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

func validHTTPHeaderName(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		switch c := value[i]; {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)):
		default:
			return false
		}
	}
	return true
}

// validHTTPHeaderValue matches Go's HTTP transport rule by rejecting control
// bytes other than horizontal tab.
func validHTTPHeaderValue(value string) bool {
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c != '\t' && (c < ' ' || c == 0x7f) {
			return false
		}
	}
	return true
}
