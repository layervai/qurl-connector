// Package audit emits per-decision audit entries from the qURL
// connector's control-plane paths (native registration, knock, login, proxy,
// teardown).
//
// Dual-sink design: each entry is written both to a local rotated
// JSONL file (forensic-grade local audit) and mirrored through
// slog.Default() at INFO level (central log shippers — journald,
// CloudWatch, GCP Logging — catch the same stream without bind-
// mounting the file). The slog mirror is opt-out via
// LoggerConfig.MirrorSlog so a customer who only wants the file (no
// central shipper interleave) can disable it.
//
// Rotation is delegated to gopkg.in/natefinch/lumberjack.v2 — the
// industry-standard, single-purpose Go log rotation library. Size,
// age, count, and gzip-compression knobs live on RotationConfig; the
// Default* constants in rotation.go describe the production defaults.
//
// Event taxonomy: the Event* constants in entry.go are a stable wire
// surface — see their godoc for the rename / breaking-change contract.
package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultBufferSize = 4096
	flushInterval     = 1 * time.Second
	flushBytes        = 64 * 1024 // 64 KB

	// dropWarnInterval bounds the rate at which buffer-full drop
	// warnings are emitted through slog. Without this bound a sustained
	// drop episode would itself flood the log pipeline that the audit
	// drops were already failing to reach. The visible-per-minute
	// budget (1 warning, drop count attached) gives operators enough
	// signal to alert on without out-of-band paging from the warning
	// stream itself.
	dropWarnInterval = 1 * time.Minute
)

// Logger is the audit logging interface.
type Logger interface {
	Log(entry Entry)
	Close() error
}

// NopLogger is a no-op logger for testing or when audit is disabled.
type NopLogger struct{}

func (NopLogger) Log(Entry)    {}
func (NopLogger) Close() error { return nil }

// defaultLogger holds the process-wide audit Logger registered by
// cmd/frpc at startup. Command call sites reach for Default() rather than threading a Logger
// through every function signature — mirrors the slog.Default pattern
// used elsewhere in this repo.
//
// Stored as Logger (interface) rather than *JSONLLogger so test code
// can install a fake without touching the file/rotator path. The
// atomic.Pointer guarantees the read+swap is race-free for any
// late-bound SetDefault calls (test setup, fault-injection wrappers).
var defaultLogger atomic.Pointer[Logger]

// SetDefault installs the process-wide audit Logger. Passing nil
// resets to the NopLogger fallback. Returns the previous Logger so
// test setup can restore on cleanup.
//
// Safe for concurrent use. Typical call site: cmd/frpc's runCmdFunc
// constructs a JSONLLogger and calls SetDefault before any emit site
// fires; tests use a fakeLogger and restore in t.Cleanup.
func SetDefault(l Logger) Logger {
	var prev Logger
	if old := defaultLogger.Load(); old != nil {
		prev = *old
	} else {
		prev = NopLogger{}
	}
	if l == nil {
		defaultLogger.Store(nil)
		return prev
	}
	defaultLogger.Store(&l)
	return prev
}

// Default returns the process-wide audit Logger. Falls back to a
// NopLogger when SetDefault has not been called — so emit sites are
// always safe to call without a nil check, mirroring slog.Default's
// contract.
func Default() Logger {
	if p := defaultLogger.Load(); p != nil {
		return *p
	}
	return NopLogger{}
}

// LoggerConfig configures a JSONLLogger.
type LoggerConfig struct {
	// FilePath is the active audit file path. Lumberjack creates
	// rotated backups next to it (filename-2026-05-26T12-00-00.000.log
	// shape). Required.
	FilePath string

	// Rotation is the size/age/count policy applied to FilePath. Zero
	// values fall through to the Default* constants in rotation.go.
	Rotation RotationConfig

	// BufferSize is the entry channel buffer; 0 means defaultBufferSize.
	BufferSize int

	// MirrorSlog, when true, mirrors each entry through slog.Default()
	// at INFO level so central log shippers can consume the stream
	// without bind-mounting the file. Default is set at construction
	// time via NewJSONLLogger's plumbing — leave false to disable.
	MirrorSlog bool

	MachineID string
	Version   string

	// Actor is stamped onto every entry. Typically QURL_CONNECTOR_AGENT_ID (or
	// the state-file UUIDv7 fallback). Empty → field omitted on
	// individual entries.
	Actor string
}

// JSONLLogger writes audit entries as newline-delimited JSON to a
// rotated file AND (optionally) mirrors them through slog.Default at
// INFO level. It is safe for concurrent use from multiple goroutines —
// the Log method funnels onto a single internal channel and one
// goroutine owns all writes to the rotator + slog.
type JSONLLogger struct {
	ch        chan Entry
	rotator   io.WriteCloser
	done      chan struct{}
	closeOnce sync.Once
	machineID string
	version   string
	actor     string
	mirror    bool

	// dropped counts entries dropped because the channel buffer was
	// full. Read by tests; written by Log under a fast atomic. The
	// run() goroutine drains it on a ticker and emits a rate-limited
	// slog.Warn so a sustained drop episode is observable without
	// flooding the log pipeline.
	dropped atomic.Uint64
}

// auditFileMode is the on-disk permission the active audit file
// and rotated backups MUST carry. Owner-only — audit entries
// include source IPs and session IDs and must not be world-readable
// even on a multi-tenant host. The pre-lumberjack implementation
// enforced this via `os.OpenFile(..., 0o600)`; the lumberjack-
// backed implementation enforces it via preCreateAuditFileAt0600
// at construction time AND via os.Chmod whenever the file is
// re-opened on subsequent constructor calls.
const auditFileMode os.FileMode = 0o600

// preCreateAuditFileAt0600 ensures the file at path exists and is
// owner-only readable/writable before lumberjack ever opens it. The
// call is idempotent: if the file already exists, we explicitly
// re-chmod it to 0o600 so an upgrade from a hypothetical mode-
// drifted prior install converges. Returns the first error from
// OpenFile / Chmod; bare-file errors propagate so the caller (the
// NewJSONLLogger contract) can surface them at construction time.
func preCreateAuditFileAt0600(path string) error {
	// O_CREATE | O_WRONLY | O_APPEND with explicit mode 0o600 mirrors
	// the prior pre-lumberjack OpenFile contract. We close
	// immediately; lumberjack owns the long-lived fd. The file's mode
	// is set by OpenFile only on the create branch — pre-existing
	// files keep their mode, so we follow with an explicit Chmod to
	// converge regardless of starting state.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, auditFileMode)
	if err != nil {
		return err
	}
	if closeErr := f.Close(); closeErr != nil {
		return closeErr
	}
	// Chmod is a no-op on a freshly-created file (already 0o600 from
	// OpenFile) and corrects a pre-existing file whose mode drifted.
	// Errors here are surfaced — silently leaving an over-permissive
	// audit file in place would defeat the whole point of this
	// helper.
	return os.Chmod(path, auditFileMode)
}

// NewJSONLLogger creates a new JSONL audit logger. It creates parent
// directories if they do not exist, opens the file for append via the
// rotator, and starts a background goroutine that drains the entry
// channel to disk + (optionally) to slog.
func NewJSONLLogger(cfg LoggerConfig) (*JSONLLogger, error) {
	if cfg.FilePath == "" {
		return nil, fmt.Errorf("audit: FilePath is required")
	}

	// Create parent directories. Lumberjack also MkdirAll-s on first
	// write, but doing it here surfaces a permission / read-only-fs
	// failure at construction time rather than at the first Log call,
	// which is the contract callers expect from the previous version.
	dir := filepath.Dir(cfg.FilePath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("audit: create directories: %w", err)
	}

	// Pre-create / re-chmod the audit file at 0o600 BEFORE handing
	// the path to lumberjack. Audit logs contain source IPs and
	// session IDs — owner-only is the same posture the prior
	// pre-lumberjack implementation explicitly maintained via
	// `os.OpenFile(..., 0o600)`. Lumberjack v2.2.1 doesn't expose a
	// FileMode knob; its `openNew` uses 0o600 for brand-new files
	// but COPIES the existing file's mode for an already-present
	// file (lumberjack.go:218-219). Pre-touching here covers both
	// branches: a fresh install gets 0o600 from this OpenFile, and
	// an upgrade from a hypothetical mode-drifted file gets
	// re-chmodded to 0o600.
	if err := preCreateAuditFileAt0600(cfg.FilePath); err != nil {
		return nil, fmt.Errorf("audit: pre-create file at 0o600: %w", err)
	}

	rotator := newRotatingWriter(cfg.FilePath, cfg.Rotation)

	bufSize := cfg.BufferSize
	if bufSize <= 0 {
		bufSize = defaultBufferSize
	}

	l := &JSONLLogger{
		ch:        make(chan Entry, bufSize),
		rotator:   rotator,
		done:      make(chan struct{}),
		machineID: cfg.MachineID,
		version:   cfg.Version,
		actor:     cfg.Actor,
		mirror:    cfg.MirrorSlog,
	}

	go l.run()
	return l, nil
}

// Log enqueues an entry for async writing. Stamping policy:
//
//   - Timestamp: ALWAYS overwritten with time.Now().UTC(). Audit
//     entries are forensic-grade — caller-supplied timestamps would
//     open a "stale-timestamp from a retry queue" failure mode that
//     would silently land an entry minutes / hours after the
//     decision it claims to describe. The pre-PR behavior also
//     unconditionally stamped here; preserved verbatim.
//   - MachineID / ProxyVersion: stamped only when the caller left
//     them empty. These are process-stable fields (machine id and
//     build version don't change mid-process), so a caller could in
//     principle pre-populate them; the overwrite-only-if-empty
//     pattern keeps tests deterministic when they want to verify
//     a specific value flows through.
//   - Actor: stamped only when the caller left it empty. The
//     native-registration path explicitly supplies the agent ID per entry
//     because the YAML-loaded actor isn't known yet; later (post-
//     YAML-swap) emit sites that leave Actor empty inherit the
//     swapped logger's configured Actor.
//
// If the internal buffer is full the entry is dropped and a counter
// is incremented; the background goroutine emits a rate-limited
// slog.Warn naming the total drop count so a sustained drop episode
// is observable in the central log shipper.
//
// Send-on-closed-channel safety: emit sites read audit.Default()
// and then call Log without holding any lock against
// swapAuditLoggerFromYAML. The swap calls Close → close(l.ch), so
// an unlucky goroutine that loaded the pre-swap Logger pointer
// JUST BEFORE the swap can race a send into a now-closed channel,
// which panics in Go regardless of the `default` branch. We
// recover() the panic so the data plane never crashes on a benign
// swap race; the entry is accounted as a drop. The alternative
// (sync.RWMutex around every send + close) would force the hot
// Log path through a contended lock for a race that can only fire
// once at YAML-load time — recover is the cheaper guard.
//
// NB: recover only fires on the closed-channel panic; any other
// panic from inside Log (e.g., a future caller mutating the entry
// concurrently) would also be swallowed. The function is small and
// allocation-free outside the send; if a regression introduces a
// different panic source here, drop counter rate-of-change is the
// observable signal.
func (l *JSONLLogger) Log(entry Entry) {
	if entry.MachineID == "" {
		entry.MachineID = l.machineID
	}
	if entry.ProxyVersion == "" {
		entry.ProxyVersion = l.version
	}
	if entry.Actor == "" {
		entry.Actor = l.actor
	}
	// Timestamp is ALWAYS overwritten — see Log godoc for rationale.
	// Caller-supplied timestamps would defeat the forensic-grade
	// guarantee that ts is the wall-clock moment Log was called.
	entry.Timestamp = time.Now().UTC()

	// recover() guards the send-on-closed-channel panic — see Log
	// godoc. The deferred call increments the drop counter on the
	// panic path so a swap-race entry is accounted, not silently
	// lost.
	defer func() {
		if r := recover(); r != nil {
			l.dropped.Add(1)
		}
	}()
	select {
	case l.ch <- entry:
	default:
		l.dropped.Add(1)
	}
}

// Close signals the background goroutine to stop, waits for it to drain
// all remaining entries, and closes the underlying rotator.
func (l *JSONLLogger) Close() error {
	var err error
	l.closeOnce.Do(func() {
		close(l.ch)
		<-l.done
		err = l.rotator.Close()
	})
	return err
}

// DroppedCount returns the cumulative number of entries dropped due to
// the channel buffer being full. Exported for tests and (future) admin/
// metrics surfaces; not part of the Logger interface contract.
func (l *JSONLLogger) DroppedCount() uint64 {
	return l.dropped.Load()
}

// run is the background goroutine that reads entries from the channel,
// JSON-encodes them to the rotator's bufio.Writer, and (optionally)
// mirrors each entry through slog. It flushes the bufio.Writer
// periodically or when the buffer exceeds flushBytes. The drop-warn
// timer fires on the same cadence as flushInterval but only emits when
// the drop counter has moved since the last warning.
func (l *JSONLLogger) run() {
	defer close(l.done)

	bw := bufio.NewWriterSize(l.rotator, flushBytes)
	flushTicker := time.NewTicker(flushInterval)
	defer flushTicker.Stop()
	dropWarnTicker := time.NewTicker(dropWarnInterval)
	defer dropWarnTicker.Stop()

	enc := json.NewEncoder(bw)
	var lastDropWarned uint64

	for {
		select {
		case entry, ok := <-l.ch:
			if !ok {
				// Channel closed — drain is complete.
				_ = bw.Flush()
				// Final drop summary at shutdown so an episode that
				// fell entirely inside the warn-interval still surfaces.
				if total := l.dropped.Load(); total > lastDropWarned {
					slog.Warn("audit: buffer-full drops at shutdown",
						"dropped_total", total,
						"dropped_since_last_warn", total-lastDropWarned,
					)
				}
				return
			}
			if encErr := enc.Encode(entry); encErr != nil {
				// json.Encoder calls bw.Write under the hood; a non-
				// nil err here means the rotator's write failed (eg
				// disk-full). One stderr line per occurrence + a slog
				// mirror — but no panic: audit must not take down the
				// data plane.
				fmt.Fprintf(os.Stderr, "audit: encode/write failed: %v\n", encErr)
				slog.Warn("audit: encode/write failed",
					"err", encErr.Error(),
					"event", entry.Event,
				)
			}
			if bw.Buffered() >= flushBytes {
				_ = bw.Flush()
			}
			if l.mirror {
				mirrorToSlog(entry)
			}
		case <-flushTicker.C:
			_ = bw.Flush()
		case <-dropWarnTicker.C:
			if total := l.dropped.Load(); total > lastDropWarned {
				slog.Warn("audit: buffer-full drops observed",
					"dropped_total", total,
					"dropped_since_last_warn", total-lastDropWarned,
				)
				lastDropWarned = total
			}
		}
	}
}

// mirrorToSlog emits an audit entry through slog.Default() at INFO
// level so central log shippers see the same stream as the file. The
// event name is used as the slog message; entry fields are attached as
// structured attrs. Empty fields are omitted to keep the central
// stream compact.
//
// Why INFO (not WARN/ERROR even for deny/error outcomes): audit
// entries describe DECISIONS, not failures of the audit pipeline
// itself. A deny is a correct policy outcome; emitting it at ERROR
// would trigger error-rate dashboards / alerts that exist to detect
// real malfunctions. Outcome is carried as a structured attr so log-
// pipeline filters can route deny/error entries to security alerting
// without conflating with infrastructure alerting.
//
// Context handling — v1 limitation: uses context.Background() so the
// emit-site request context (trace IDs, deadlines) does NOT propagate
// to the slog record. The audit channel hand-off in run() decouples
// the calling goroutine from the encoder goroutine, so the original
// ctx is no longer alive at this point. A future iteration could
// thread emit-site ctx through Entry (or a parallel channel) if
// downstream log shippers start requiring per-request trace
// correlation via slog attrs the handler reads from ctx. Today the
// TraceID Entry field covers the correlation case via the structured
// attr below.
//
// Intentionally-omitted Entry fields: SourcePort, BytesSent,
// BytesRecv. These exist on Entry (and roundtrip
// through the JSONL file sink) but are deliberately NOT mirrored
// to slog — they're file-only forensic fields whose cardinality
// would balloon the per-record size in central log shippers
// without adding signal the dashboards key on. If a future
// dashboard starts requiring one of these, lift it explicitly
// here in the same way the listed fields are (no implicit
// reflection). Action is mirrored for backward-compat with legacy
// filters; new pipelines should key on Outcome.
func mirrorToSlog(entry Entry) {
	attrs := make([]slog.Attr, 0, 17)
	// Emit ts explicitly so the slog record's "ts" attr matches the
	// file's "ts" field. slog's handler otherwise stamps its own
	// time at record-build time, which is encoder-goroutine drain
	// time — for a backed-up channel that drift can be hundreds of
	// ms, and central log shippers correlating file ↔ slog on time
	// would see mismatched timestamps. The slog.Record itself still
	// carries its handler-stamped Time; this attr is the explicit
	// audit-defined wall-clock from Log() that downstream consumers
	// should key on.
	attrs = append(attrs, slog.Time("ts", entry.Timestamp))
	if entry.Outcome != "" {
		attrs = append(attrs, slog.String("outcome", string(entry.Outcome)))
	}
	if entry.Action != "" {
		attrs = append(attrs, slog.String("action", string(entry.Action)))
	}
	if entry.Actor != "" {
		attrs = append(attrs, slog.String("actor", entry.Actor))
	}
	if entry.TraceID != "" {
		attrs = append(attrs, slog.String("trace_id", entry.TraceID))
	}
	if entry.RunID != "" {
		attrs = append(attrs, slog.String("run_id", entry.RunID))
	}
	if entry.Reason != "" {
		attrs = append(attrs, slog.String("reason", entry.Reason))
	}
	if entry.ResourceID != "" {
		attrs = append(attrs, slog.String("resource_id", entry.ResourceID))
	}
	if entry.RouteID != "" {
		attrs = append(attrs, slog.String("route_id", entry.RouteID))
	}
	if entry.SessionID != "" {
		attrs = append(attrs, slog.String("session_id", entry.SessionID))
	}
	if entry.Subject != "" {
		attrs = append(attrs, slog.String("subject", entry.Subject))
	}
	if entry.SourceIP != "" {
		attrs = append(attrs, slog.String("source_ip", entry.SourceIP))
	}
	if entry.Target != "" {
		attrs = append(attrs, slog.String("target", entry.Target))
	}
	if entry.MachineID != "" {
		attrs = append(attrs, slog.String("machine_id", entry.MachineID))
	}
	if entry.ProxyVersion != "" {
		attrs = append(attrs, slog.String("proxy_version", entry.ProxyVersion))
	}
	if entry.LatencyMS != 0 {
		attrs = append(attrs, slog.Float64("latency_ms", entry.LatencyMS))
	}
	if entry.Error != "" {
		attrs = append(attrs, slog.String("error", entry.Error))
	}
	slog.LogAttrs(context.Background(), slog.LevelInfo, entry.Event, attrs...)
}
