package audit

import "time"

// Action describes the outcome of an access attempt.
//
// The legacy Action* constants below predate the Event* audit taxonomy
// (see below) and survive as-is to keep the existing JSONLLogger test
// surface and any downstream log-pipeline filters stable. New emit
// sites should populate Outcome with one of the Outcome* constants —
// Outcome is the field dashboards key on.
type Action string

const (
	ActionAllow                Action = "allow"
	ActionDenyNoSession        Action = "deny_no_session"
	ActionDenyInvalidSignature Action = "deny_invalid_signature"
	ActionDenyExpired          Action = "deny_expired"
	ActionDenyUnknownResource  Action = "deny_unknown_resource"
	ActionDenyOneTimeConsumed  Action = "deny_one_time_consumed"
	ActionDenyRateLimited      Action = "deny_rate_limited"
	ActionDenyIPPolicy         Action = "deny_ip_policy"
	ActionDenyMalformed        Action = "deny_malformed"
	ActionDenyMissingClaims    Action = "deny_missing_claims"
	ActionError                Action = "error"
)

// Outcome classifies a per-decision audit entry into the four states
// the event taxonomy uses (see Event* below). Distinct from Action:
// Action carries the legacy reject-tag detail (deny_expired,
// deny_rate_limited, …); Outcome is the coarse pass/fail axis the
// dashboards and alerting pipelines bucket on.
//
// Keep this list aligned with the Event* taxonomy below (success ↔
// *.success, deny ↔ *.deny, error ↔ *.error, allow ↔
// qurl.connector.proxy.allow).
type Outcome string

const (
	// OutcomeSuccess is the happy-path outcome for the registration / knock
	// / login decisions — the prerequisite was satisfied and the next
	// stage may proceed.
	OutcomeSuccess Outcome = "success"
	// OutcomeAllow is the proxy-registration outcome
	// (qurl.connector.proxy.allow); the AC/tunnel-server admitted the
	// route into the dispatch table. Distinct from OutcomeSuccess so
	// dashboards can split "connector came up" from "route was
	// admitted".
	OutcomeAllow Outcome = "allow"
	// OutcomeDeny is a policy-driven refusal (bad pubkey, expired
	// knock, unknown resource, rate limit). Reason is populated with
	// the specific cause; Error is empty on this path.
	OutcomeDeny Outcome = "deny"
	// OutcomeError is a transport / parse / crypto failure that wasn't
	// a policy decision (timeout, malformed response, dial refused).
	// Error carries the underlying message; Reason is set to a stable
	// category tag where the call site can classify it.
	OutcomeError Outcome = "error"
)

// Event names for the audit taxonomy. These strings are a stable wire
// surface: they populate the `event` field of every emitted entry
// (JSONL file + slog mirror) and are documented for operators on the
// public qURL connector audit-logging documentation.
//
// Cross-repo note: a matching server-side taxonomy (the server half of
// login.* / proxy.*) is not emitted by qURL tunnel server today
// — the connector is the sole emitter. If one ever lands, give it these
// same names.
//
// Renaming one of these is a breaking change for any consumer that
// filters on the string — update those docs (and the website's
// docs-content CI test) in the same change, plus any external
// log-pipeline alert or dashboard keyed on the old name.
const (
	EventBootstrapSuccess = "qurl.connector.bootstrap.success"
	EventBootstrapDeny    = "qurl.connector.bootstrap.deny"
	EventBootstrapError   = "qurl.connector.bootstrap.error"

	EventKnockSuccess = "qurl.connector.knock.success"
	EventKnockDeny    = "qurl.connector.knock.deny"
	EventKnockError   = "qurl.connector.knock.error"

	EventLoginSuccess = "qurl.connector.login.success"
	EventLoginDeny    = "qurl.connector.login.deny"
	EventLoginError   = "qurl.connector.login.error"

	EventProxyAllow = "qurl.connector.proxy.allow"
	// EventProxyDeny records one route being retired in place because its
	// resource is permanently unavailable while its siblings keep serving.
	// Reason says which layer refused it: resource_not_found when the
	// tunnel server refused the route's NewProxy, admission_resource_gone
	// when the knock for its admission was refused. Emitted by the
	// standalone command; a transient NewProxy retry is not a deny.
	EventProxyDeny = "qurl.connector.proxy.deny"
	// EventProxyError is reserved for taxonomy shape parity; the
	// client-side emitter is pending FRP per-proxy hooks (same
	// constraint as EventProxyDeny).
	EventProxyError = "qurl.connector.proxy.error"

	EventTeardown = "qurl.connector.teardown"
)

// Entry is a single audit log record.
//
// Field naming: JSON tags use snake_case; ts is short to keep the most-
// frequent field compact on disk. New fields land at the end of the
// JSON object on the wire — readers MUST tolerate unknown fields
// (encoding/json does so by default) so the taxonomy can ratchet
// forward without breaking existing consumers.
type Entry struct {
	Timestamp time.Time `json:"ts"`
	Event     string    `json:"event"`

	// Action is the legacy reject-tag detail; new emit sites SHOULD
	// populate Outcome instead but Action remains for the existing
	// JSONLLogger callers (NopLogger fallback, the original tests, and
	// any downstream pipeline that already filters on it).
	Action Action `json:"action,omitempty"`
	// Outcome is the coarse pass/fail axis the dashboards bucket on.
	// See the Outcome constants.
	Outcome Outcome `json:"outcome,omitempty"`

	// Actor is the agent ID (QURL_CONNECTOR_AGENT_ID, or the state-file
	// UUIDv7 fallback). Distinct from Subject — Subject is the
	// principal a decision is made ABOUT (legacy API surface, may be
	// an OAuth subject); Actor is who initiated the operation (the
	// agent itself, on every entry emitted by this binary).
	Actor string `json:"actor,omitempty"`

	// TraceID is the FRP RunID assigned at Login. Correlates across
	// qurl.connector.knock.* → qurl.connector.login.* →
	// qurl.connector.proxy.* → qurl.connector.teardown for one
	// managed session cycle. Empty before Login completes, so
	// registration/knock entries carry it only when the session is
	// re-emitting on a cycle that already has a RunID.
	TraceID string `json:"trace_id,omitempty"`

	// Reason is the structured cause for deny/error outcomes. Populated
	// with a short snake_case tag (bad_pubkey, knock_expired,
	// dial_timeout, parse_error, …) so dashboards can group by cause
	// without parsing Error free-text. Empty for success/allow.
	Reason string `json:"reason,omitempty"`

	SessionID  string `json:"session_id,omitempty"`
	ResourceID string `json:"resource_id,omitempty"`
	RouteID    string `json:"route_id,omitempty"`
	Subject    string `json:"subject,omitempty"`

	// SourceIP is the source of the operation. For outbound knock /
	// native registration this is the agent's egress IP (best-effort; may be
	// empty when the local socket address is unknown).
	SourceIP   string `json:"source_ip,omitempty"`
	SourcePort int    `json:"source_port,omitempty"`
	Target     string `json:"target,omitempty"`

	LatencyMS float64 `json:"latency_ms,omitempty"`
	BytesSent int64   `json:"bytes_sent,omitempty"`
	BytesRecv int64   `json:"bytes_received,omitempty"`

	Error        string `json:"error,omitempty"`
	MachineID    string `json:"machine_id,omitempty"`
	ProxyVersion string `json:"proxy_version,omitempty"`

	// RunID is the caller-owned native cycle RunID (qurl-go's
	// NewCycleRunID; 16 lowercase hex) the emitting managed session cycle
	// presented on its KNK and first FRP Login. Stamped on every
	// knock.* / login.* / proxy.* / teardown entry so one cycle's
	// admission chain can be grouped, and scanned by the strict-proof
	// run_id_cycle_binding scenario (pkg/strictproof). TraceID carries
	// the same value at those sites and stays for existing consumers;
	// run_id is the explicit, additive name. Empty on bootstrap.*
	// entries — native registration precedes any cycle.
	RunID string `json:"run_id,omitempty"`
}
