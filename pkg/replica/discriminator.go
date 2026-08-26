// Package replica resolves a per-replica discriminator string that
// uniquely identifies THIS process among co-deployed replicas of the
// same qurl-connector agent.
//
// Why this exists
// ----------------
// When multiple connector replicas register against the same FRP
// server under a shared LoadBalancerGroup (the headless multi-replica
// HA shape — see pkg/config/frpgen.go's buildHTTPProxy), each
// replica's FRP proxy `Name` MUST be unique across the group or FRPS
// rejects the second NewProxy with `ErrProxyRepeated` (see
// github.com/fatedier/frp/server/group/group.go:26 and
// server/group/http.go:110). The connector already derives the
// LoadBalancerGroup from connector_routing_id (so every replica shares ONE
// routing key), but `pc.Name = route.ID` collides identically — the
// per-replica salt in this package is what unblocks FRP's existing
// HTTPGroupController round-robin across replicas.
//
// Resolution order (first non-empty wins)
// ----------------------------------------
//  1. Explicit env LAYERV_REPLICA_ID — operator override; useful for tests,
//     bare-metal deploys, and any environment where the operator
//     wants the salt to be deterministic.
//  2. ECS task UUID via ECS_CONTAINER_METADATA_URI_V4 — the task ARN's
//     last segment is the per-task UUID. Fetched at boot (one HTTP
//     GET on the loopback metadata endpoint, bounded by a 2s
//     context.WithTimeout).
//  3. Hostname (os.Hostname). Container / pod / VM hostnames are
//     typically unique per replica (Kubernetes assigns each pod a
//     unique name; docker compose --scale=N assigns each container
//     a unique hostname; Nomad allocs are unique). This is the
//     SAFE default for non-ECS multi-replica orchestrators.
//  4. machineID from /etc/machine-id (and /var/lib/dbus/machine-id).
//     STABLE PER-HOST — which means SHARED across co-located replicas
//     on the same node. Safe only at one-replica-per-host (bare-
//     metal, single-VM); on Kubernetes / docker compose --scale=N
//     with multiple replicas per node, machine-id is SHARED and
//     would re-introduce the FRP NewProxy collision this package
//     fixes. Ranked AFTER hostname for that reason: hostname's
//     per-replica uniqueness is the right default; machine-id is
//     the explicit "stable, host-keyed" fallback an operator can
//     opt into via LAYERV_REPLICA_ID if they want.
//  5. Random short hex generated at process start. Persisted in memory
//     for the lifetime of the process (the resolver is sync.Once-
//     latched). This branch logs a warning via the caller — see
//     Resolve's Metadata return.
//
// Multi-replica-per-host orchestrators: set LAYERV_REPLICA_ID explicitly
// (e.g. via the per-replica downward-API in Kubernetes:
// `valueFrom: { fieldRef: { fieldPath: metadata.name } }`). The
// hostname branch covers the common orchestrator case automatically,
// but it relies on the substrate actually assigning unique hostnames;
// cloned VMs or custom runtimes that reuse hostnames must set
// LAYERV_REPLICA_ID.
//
// All discriminators are normalized via Normalize: lowercase, filter
// to [0-9a-z-], collapse consecutive hyphens, strip leading/trailing
// hyphens, trim to MaxDiscriminatorLen. For stable host identifiers
// that should not be rendered directly (machine-id), the resolver
// hashes first and then normalizes the hex digest. The combined
// `${route.ID}-${discriminator}` thus stays DNS-safe and well under
// any wire limit a future FRP bump might introduce. LayerV FRP
// v0.70.0-layerv.5 has
// no proxy-name length validation today (grep -rn 'len(.*Name)' on
// the server side returns zero hits in
// `pkg/config/v1/validation/`) but the cap is defense in depth.
//
// Determinism
// -----------
// Resolve is idempotent within one process lifetime: the same call
// shape returns the same discriminator regardless of how many times
// it's invoked. The internal sync.Once latch carries this. Across
// process restarts the discriminator is REGENERATED — the random-
// fallback branch picks a fresh value, and the ECS/machine-id
// branches refetch from the live environment (which may have
// changed: an ECS task replacement gets a NEW UUID, which is
// exactly the property the salt needs to deduplicate against the
// old task during overlap windows).
//
// Process-singleton scope
// ------------------------
// The resolver's cache (resolveOnce / cachedValue / cachedMeta /
// cachedErrors) lives on the Resolver value, NOT package-level.
// Per-process stability comes from the CALLER, not the Resolver:
// cmd/frpc's resolveReplicaDiscriminator writes the resolved value
// into cfg.Server.ReplicaDiscriminator at boot, and the managed session
// treats the FRP Common / proxy configs as read-only across reconnect cycles. Subsequent
// `resolveReplicaDiscriminator` calls (none today) would take the
// explicit-YAML branch on the cached value and re-normalize
// idempotently. Tests construct a fresh Resolver per test, which
// gives each test an isolated cache without any shared global to
// reset.
//
// Reload caveat: if a FUTURE runtime wires admin live-reload or
// restart-on-config-change and re-parses the YAML into a fresh
// `cfg` (resetting cfg.Server.ReplicaDiscriminator to whatever the
// YAML had), the random-fallback branch will pick a NEW salt and
// the prior FRPS registration lingers until it times out — exactly
// the ErrProxyRepeated this package exists to avoid. The fix in
// that future state is to PERSIST the random fallback to
// `<state_dir>/replica_discriminator` (mirroring how pkg/agentstate
// persists the agent UUID for connector_identities.json continuity).
// Not implemented today because today's resolver only runs once.
package replica

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// EnvReplicaID is the explicit operator override. When set non-empty
// (after whitespace trim), it short-circuits the resolution chain.
//
// Naming convention: LAYERV_* matches the rest of the connector's
// operator-facing env namespace (QURL_CONNECTOR_AGENT_ID, LAYERV_KEY_PROVIDER,
// QURL_CONNECTOR_STATE_DIR, etc). A bare
// REPLICA_ID would risk collision with unrelated orchestrator /
// tooling env (k8s downward-API + helm chart defaults occasionally
// surface generic REPLICA_* names).
//
// Use cases: deterministic salts in tests; bare-metal deploys where
// the operator wants the salt to be a human-meaningful tag (e.g.
// `replica-1`, `replica-2`); multi-replica-per-host orchestrators
// where neither ECS metadata nor hostname is unique-per-replica
// (typical Kubernetes downward-API pattern:
// `valueFrom: { fieldRef: { fieldPath: metadata.name } }`); blue/
// green cutover staging where two concurrent agents need different
// salts to avoid the brief overlap window's NewProxy collision.
const EnvReplicaID = "LAYERV_REPLICA_ID"

// EnvECSContainerMetadataURI is the AWS-injected ECS task metadata
// endpoint (the v4 shape; v3 is deprecated). When the task runs on
// Fargate or EC2-backed ECS, AWS injects this variable into the
// container env unconditionally. Absent → not on ECS.
const EnvECSContainerMetadataURI = "ECS_CONTAINER_METADATA_URI_V4"

// MaxDiscriminatorLen caps the discriminator at 16 chars. The
// rendered FRP proxy name is `${route.ID}-${discriminator}`; with
// route.ID typically 16-32 chars (a `r_<hex>` resource_id), this
// keeps the combined name well under any reasonable wire limit. 16
// chars of base16 = 64 bits of entropy in the random-fallback
// branch — enough to make a collision over the lifetime of one ECS
// service vanishingly unlikely at typical replica counts.
const MaxDiscriminatorLen = 16

const hashSuffixLen = 8

// Source identifies which branch of the resolver returned the value.
// Surfaced in the Metadata returned by Resolve so the caller can log
// the source at INFO once per process and emit it via metrics.
type Source string

const (
	SourceEnv            Source = "env"
	SourceECS            Source = "ecs"
	SourceHostname       Source = "hostname"
	SourceMachineID      Source = "machine-id"
	SourceRandomFallback Source = "random-fallback"
	// SourceExplicit identifies the YAML-set escape hatch
	// (cfg.Server.ReplicaDiscriminator). The resolver itself never
	// returns this — Resolve consumers (cmd/frpc/run.go) emit it
	// when the YAML field is non-empty and the resolver chain is
	// bypassed entirely. Kept in this package so the Source
	// vocabulary is single-sourced.
	SourceExplicit Source = "explicit-yaml"
)

// Metadata describes WHY a particular discriminator was returned so
// the boot-time log line and any metrics emit can carry the source
// label. Returned alongside the string from Resolve.
type Metadata struct {
	// Source is the branch of the resolution chain that produced
	// the discriminator. See the Source constants.
	Source Source

	// Raw is the pre-normalization value the source produced (the
	// untrimmed env var, the raw ECS task UUID, etc). Logged for
	// audit; not used downstream.
	Raw string

	// Warning is set when a non-canonical branch fired (today: just
	// SourceRandomFallback). Empty for canonical branches. The
	// caller emits this as a slog.Warn so operators see "this
	// process is using a non-stable salt" without the log line
	// being lost in the boot banner noise.
	Warning string
}

// MachineIDReader is injected for tests; production callers use the
// nil sentinel which resolves to defaultMachineIDReader
// (reads /etc/machine-id then /var/lib/dbus/machine-id).
//
// pkg/agentstate uses github.com/denisbrodbeck/machineid for the
// agent's OWN durable identity; this package deliberately reads
// /etc/machine-id directly to avoid pulling that dependency into a
// pure-stdlib resolver and to keep the SourceMachineID branch
// minimal. Hostname covers macOS / BSD shapes that lack
// /etc/machine-id.
type MachineIDReader func() (string, error)

// HostnameReader is injected for tests; production callers use the
// nil sentinel which resolves to os.Hostname.
type HostnameReader func() (string, error)

// ECSFetcher is injected for tests; production callers use the nil
// sentinel which resolves to defaultECSFetcher (a 2s-context-bounded
// GET on ${ECS_CONTAINER_METADATA_URI_V4}/task).
type ECSFetcher func(ctx context.Context, endpoint string) (string, error)

// Resolver wires the optional injection points + caches the resolved
// salt for the process. Construct ONCE per process at boot
// (cmd/frpc/run.go's resolveReplicaDiscriminator) and reuse — the
// cache fields are populated under sync.Once on the first Resolve
// call.
//
// The zero value is the production resolver: all readers nil → all
// defaults resolved internally. Tests use named-field literals to
// inject deterministic readers.
type Resolver struct {
	Env      map[string]string // when non-nil, used in lieu of os.LookupEnv (tests)
	Machine  MachineIDReader   // nil → defaultMachineIDReader
	Hostname HostnameReader    // nil → os.Hostname
	ECS      ECSFetcher        // nil → defaultECSFetcher
	RandRead func(b []byte) (int, error)

	// Cache populated under once on the first Resolve call. softErrors
	// and warnings are guarded so read-only introspection stays race-free
	// even if a caller asks while Resolve is still walking fallbacks.
	once       sync.Once
	mu         sync.Mutex
	cached     string
	cachedMeta Metadata
	softErrors []error
	warnings   []string
}

// Resolve walks the resolution chain and returns the discriminator +
// metadata. Latched once per Resolver via sync.Once: subsequent
// calls return the SAME value/metadata regardless of environment
// changes (the salt is a boot-time property; it must NOT drift mid-
// process or the FRP proxy registrations themselves would drift).
//
// The error return is always nil today: every branch either returns
// a value or falls through to the next, and the random fallback
// degrades a crypto/rand failure to a literal `no-entropy` sentinel
// rather than failing the resolver (a crypto/rand entropy outage
// breaks every TLS handshake the process would attempt next anyway,
// so failing the salt resolver on top is noise). The signature keeps
// the error return for forward compatibility with a future hard-fail
// mode (e.g. CONFIG_REQUIRE_STABLE_DISCRIMINATOR) that promotes the
// no-entropy sentinel into a returned error.
func (r *Resolver) Resolve(ctx context.Context) (string, Metadata, error) {
	r.once.Do(func() {
		r.cached, r.cachedMeta = r.resolveOnce(ctx)
	})
	return r.cached, r.cachedMeta, nil
}

// Errors returns the soft errors accumulated across earlier resolution
// branches (e.g. an ECS metadata fetch that timed out before the
// resolver fell through to hostname). Returns nil when no soft errors
// fired. Wrapped via errors.Join for the caller to errors.Is /
// errors.As against.
//
// Concurrency: safe to call concurrently with Resolve. If Resolve is
// still walking fallback branches, Errors observes the soft errors that
// have accumulated so far.
func (r *Resolver) Errors() error {
	r.mu.Lock()
	errs := append([]error(nil), r.softErrors...)
	r.mu.Unlock()
	if len(errs) == 0 {
		return nil
	}
	return errors.Join(errs...)
}

// Warnings returns non-fatal operator-facing warnings accumulated while
// resolving earlier branches. Unlike Errors, these should be surfaced at
// warn level because they usually mean an explicit operator override was
// ignored (for example LAYERV_REPLICA_ID containing no usable glyphs).
func (r *Resolver) Warnings() []string {
	r.mu.Lock()
	warnings := append([]string(nil), r.warnings...)
	r.mu.Unlock()
	if len(warnings) == 0 {
		return nil
	}
	return warnings
}

func (r *Resolver) appendSoftError(err error) {
	r.mu.Lock()
	r.softErrors = append(r.softErrors, err)
	r.mu.Unlock()
}

func (r *Resolver) appendWarning(warning string) {
	r.mu.Lock()
	r.warnings = append(r.warnings, warning)
	r.mu.Unlock()
}

func (r *Resolver) lookupEnv(key string) (string, bool) {
	if r.Env != nil {
		v, ok := r.Env[key]
		return v, ok
	}
	return os.LookupEnv(key)
}

func (r *Resolver) machineID() (string, error) {
	if r.Machine != nil {
		return r.Machine()
	}
	return defaultMachineIDReader()
}

func (r *Resolver) hostname() (string, error) {
	if r.Hostname != nil {
		return r.Hostname()
	}
	return os.Hostname()
}

func (r *Resolver) ecs(ctx context.Context, endpoint string) (string, error) {
	if r.ECS != nil {
		return r.ECS(ctx, endpoint)
	}
	return defaultECSFetcher(ctx, endpoint)
}

func (r *Resolver) randomHex(n int) (string, error) {
	if n <= 0 {
		return "", fmt.Errorf("invalid random length %d", n)
	}
	buf := make([]byte, (n+1)/2)
	read := rand.Read
	if r.RandRead != nil {
		read = r.RandRead
	}
	readN, err := read(buf)
	if err != nil {
		return "", err
	}
	if readN != len(buf) {
		return "", io.ErrUnexpectedEOF
	}
	out := hex.EncodeToString(buf)
	if len(out) > n {
		out = out[:n]
	}
	return out, nil
}

// resolveOnce is the single-pass body invoked under sync.Once. Returns
// the resolved value + metadata. Never returns an error — exhausting
// every branch lands on the random fallback, which itself degrades a
// crypto/rand entropy outage to a "no-entropy" sentinel + warning.
func (r *Resolver) resolveOnce(ctx context.Context) (string, Metadata) {
	// 1. Explicit env LAYERV_REPLICA_ID
	if v, ok := r.lookupEnv(EnvReplicaID); ok {
		if trimmed := Normalize(v); trimmed != "" {
			return trimmed, Metadata{Source: SourceEnv, Raw: v}
		}
		if strings.TrimSpace(v) != "" {
			r.appendWarning(fmt.Sprintf("%s dropped after normalization; falling through to resolver chain", EnvReplicaID))
		}
	}

	// 2. ECS task UUID
	if endpoint, ok := r.lookupEnv(EnvECSContainerMetadataURI); ok && strings.TrimSpace(endpoint) != "" {
		fetchCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		raw, err := r.ecs(fetchCtx, strings.TrimSpace(endpoint))
		cancel()
		if err == nil {
			uuid := extractECSTaskUUID(raw)
			if uuid != "" {
				if trimmed := Normalize(uuid); trimmed != "" {
					return trimmed, Metadata{Source: SourceECS, Raw: uuid}
				}
				r.appendSoftError(fmt.Errorf("ecs metadata task UUID normalized empty: %q", uuid))
			} else {
				r.appendSoftError(errors.New("ecs metadata missing usable TaskARN UUID"))
			}
		} else {
			r.appendSoftError(fmt.Errorf("ecs metadata fetch: %w", err))
		}
	}

	// 3. hostname (preferred over machine-id because container /
	//    pod / VM hostnames are typically unique-per-replica,
	//    whereas /etc/machine-id is host-keyed and would re-
	//    introduce the FRP NewProxy collision on multi-replica-per-
	//    host orchestrators — see the package doc).
	if h, err := r.hostname(); err == nil {
		if trimmed := Normalize(h); trimmed != "" {
			return trimmed, Metadata{Source: SourceHostname, Raw: h}
		}
	} else {
		r.appendSoftError(fmt.Errorf("hostname read: %w", err))
	}

	// 4. machine-id (host-keyed; safe only at one-replica-per-host)
	if id, err := r.machineID(); err == nil {
		if trimmed := normalizeHashed(id); trimmed != "" {
			// Do not populate Metadata.Raw for machine-id: systemd
			// recommends never exposing the stable host identifier
			// directly. The hashed discriminator is enough for logs.
			return trimmed, Metadata{Source: SourceMachineID}
		}
	} else {
		r.appendSoftError(fmt.Errorf("machine-id read: %w", err))
	}

	// 5. random fallback
	rnd, err := r.randomHex(MaxDiscriminatorLen)
	if err != nil {
		r.appendSoftError(fmt.Errorf("random fallback: %w", err))
		// crypto/rand entropy outage. We can't proceed without a
		// salt, but every other connector subsystem (TLS handshake,
		// NHP keypair generation) would fail too — degrade to a
		// fixed sentinel and log loudly. The empty value would
		// still trigger the FRP collision this package exists to
		// avoid, so we MUST return SOMETHING.
		//
		// COLLISION CAVEAT: the sentinel "no-entropy" is explicitly
		// NOT unique-per-replica — if crypto/rand fails on
		// multiple replicas simultaneously, they all return the
		// same string and FRP NewProxy collides identically. The
		// fix in that degenerate state is operator intervention
		// (LAYERV_REPLICA_ID), not a randomization workaround:
		// rand is the kernel's responsibility and the only
		// connector subsystem that could even produce a unique
		// salt in this state is the one that's broken.
		return "no-entropy", Metadata{
			Source:  SourceRandomFallback,
			Raw:     "",
			Warning: fmt.Sprintf("crypto/rand failed: %v — using non-unique sentinel salt; LAYERV_REPLICA_ID is the only available workaround until kernel entropy recovers", err),
		}
	}
	return rnd, Metadata{
		Source:  SourceRandomFallback,
		Raw:     rnd,
		Warning: "no stable identity source found; using a random per-process salt — replicas WILL re-salt across restarts (acceptable for FRP collision avoidance, but stable identity preferred via LAYERV_REPLICA_ID or ECS metadata)",
	}
}

// Normalize lower-cases, filters to [0-9a-z-], collapses consecutive
// hyphens to one, strips leading/trailing hyphens, and caps the
// result at MaxDiscriminatorLen. Normalize is intentionally idempotent:
// callers such as cmd/frpc store a canonical value for logging, while
// pkg/config.FRPProxyName normalizes again at the FRP wire boundary as
// defense in depth for direct config-generation callers.
//
// Cap behavior is COLLISION-SAFE for inputs that share a long prefix
// (Kubernetes pod names, docker-compose-scaled containers): when the
// filtered+collapsed value exceeds MaxDiscriminatorLen, we keep a
// short readable prefix of the filtered value AND append `-` + an
// 8-hex SHA-256 digest of the ORIGINAL raw input (before
// normalization). That way `fileviewer-v2-66b6c48dd5-abcde` and
// `fileviewer-v2-66b6c48dd5-fghij` — which both shrink to the same
// 16-char prefix — produce distinct salts:
//
//	"filevie-<hash8(abcde…)>"  vs  "filevie-<hash8(fghij…)>"
//
// 8 hex chars = 32 bits of entropy on the differentiating suffix; the
// birthday bound is approximately N^2 / 2^33 for N live same-prefix
// replicas. Inputs shorter than the cap are returned as-is so the
// resolver-branch ergonomics are unchanged.
//
// EXPORTED so the YAML escape hatch (cfg.Server.ReplicaDiscriminator)
// can flow through the same normalization the resolver branches apply
// — without this, a `replica_discriminator: "REPLICA_1!"` YAML value
// would render into the proxy name verbatim ("route-REPLICA_1!"),
// skipping the DNS-safe-glyph defense the package documents and that
// the FRP-client validation test fences. Callers MUST run any
// operator-supplied salt through this before stamping it on the wire.
//
// The character filter is conservative: LayerV FRP v0.70.0-layerv.5's
// `pkg/config/v1/validation/proxy.go` does no name validation at all,
// but proxy names are emitted to FRPS admin/status views and logs. The
// actual FRP routing key stays `connector_routing_id`, while
// Metas[resource_id] retains the public authorization identity. Keeping
// proxy-name glyphs DNS-safe is defense in depth for operational surfaces,
// not a vhost-routing requirement.
func Normalize(raw string) string {
	lower := strings.ToLower(strings.TrimSpace(raw))
	var b strings.Builder
	b.Grow(len(lower))
	lastWasHyphen := false
	for _, r := range lower {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(r)
			lastWasHyphen = false
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
			lastWasHyphen = false
		case r == '-':
			if !lastWasHyphen && b.Len() > 0 {
				b.WriteRune(r)
				lastWasHyphen = true
			}
		}
	}
	out := b.String()
	// Strip trailing hyphens (collapse left a single hyphen in
	// place; trim it if it ended up at the end after the filter
	// dropped the surrounding glyph). Leading-hyphen suppression
	// is handled in the loop by the b.Len() > 0 guard.
	out = strings.TrimRight(out, "-")
	if len(out) > MaxDiscriminatorLen {
		// Collision-safe truncation: take a short prefix of the
		// filtered value AND an 8-hex digest of the ORIGINAL raw
		// input. The digest covers the differentiating suffix that
		// pure prefix truncation would drop (k8s pod-name shape:
		// `<deployment>-<replicaset>-<5-char-unique>`).
		const prefixLen = MaxDiscriminatorLen - hashSuffixLen - 1
		prefix := out[:prefixLen]
		// `out[:7]` of a hyphen-collapsed string can legitimately
		// END in a hyphen if the filtered value has a hyphen at
		// position 6 (e.g. `abcdef-ghijklmn` → prefix `abcdef-`).
		// Without trimming, the join with the "-" separator emits
		// a double hyphen (`abcdef--<hash>`), violating the
		// hyphen-collapse contract this function documents. Trim
		// before the join so the result stays canonical. The
		// trimmed prefix may shrink below prefixLen — uniqueness
		// is unaffected (the hash carries the differentiation).
		prefix = strings.TrimRight(prefix, "-")
		out = prefix + "-" + shortHash(raw, hashSuffixLen)
		// Sanity-clamp in case the join produced more than the cap
		// (it shouldn't: prefixLen + 1 + hashSuffixLen = MaxDiscriminatorLen).
		if len(out) > MaxDiscriminatorLen {
			out = out[:MaxDiscriminatorLen]
		}
	}
	return out
}

func normalizeHashed(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	return Normalize(shortHash(raw, MaxDiscriminatorLen))
}

// shortHash returns the first n hex chars of sha256(raw). Used by
// Normalize for collision-safe truncation of long-shared-prefix
// inputs. Hash domain is the ORIGINAL raw input, not the filtered
// value, so two normalized-identical-prefix inputs can still diverge
// in their hash suffix (the unfiltered suffix bits feed into it).
func shortHash(raw string, n int) string {
	sum := sha256.Sum256([]byte(raw))
	hexed := hex.EncodeToString(sum[:])
	if n > len(hexed) {
		n = len(hexed)
	}
	return hexed[:n]
}

// extractECSTaskUUID parses the JSON returned by
// `${ECS_CONTAINER_METADATA_URI_V4}/task` and returns the last
// URI segment of the TaskARN (the per-task UUID). Returns "" if
// the JSON is unparseable, the TaskARN is missing, or the TaskARN
// does not contain a `/` separator — the resolver falls through to
// the next branch on empty.
func extractECSTaskUUID(body string) string {
	var payload struct {
		TaskARN string `json:"TaskARN"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		return ""
	}
	// TaskARN format:
	//   arn:aws:ecs:<region>:<account>:task/<cluster>/<uuid>
	// The UUID is the last `/`-separated segment.
	if payload.TaskARN == "" {
		return ""
	}
	taskARN := strings.TrimRight(payload.TaskARN, "/")
	if taskARN == "" {
		return ""
	}
	if i := strings.LastIndex(taskARN, "/"); i >= 0 && i+1 < len(taskARN) {
		return taskARN[i+1:]
	}
	return ""
}

// defaultMachineIDReader reads /etc/machine-id then /var/lib/dbus/
// machine-id. Returns the first one found. Other OSes / boot
// environments have their own conventions (e.g. macOS's
// IOPlatformUUID via ioreg) but the connector's deployment shape is
// Linux containers; getting fancier here would mean adding the
// machineid package as a dep just for the fallback. Hostname covers
// that branch.
func defaultMachineIDReader() (string, error) {
	for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		b, err := os.ReadFile(path)
		if err == nil {
			return strings.TrimSpace(string(b)), nil
		}
	}
	return "", errors.New("no machine-id file found")
}

// defaultECSFetcher GETs ${endpoint}/task. The 2-second deadline is
// supplied by the caller via context.WithTimeout — we do NOT also
// set http.Client.Timeout because that would be a redundant
// secondary deadline. The metadata endpoint is a loopback HTTP
// listener AWS provides on Fargate / EC2-ECS, returning the same
// JSON shape across both compute backends.
//
// Uses a DEDICATED *http.Client rather than http.DefaultClient so a
// future caller that mutates DefaultClient (e.g. a test that swaps
// the global transport) can't bleed into the metadata fetch and
// vice-versa. The client itself is zero-value (default transport),
// so behavior is identical to http.DefaultClient — the isolation is
// the only purpose.
var ecsMetadataClient = &http.Client{}

func defaultECSFetcher(ctx context.Context, endpoint string) (string, error) {
	url := strings.TrimRight(endpoint, "/") + "/task"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := ecsMetadataClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ecs metadata: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return "", err
	}
	return string(body), nil
}
