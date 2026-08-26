package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/layervai/qurl-connector/pkg/agentstate"
	"github.com/layervai/qurl-connector/pkg/audit"
	nhpconfig "github.com/layervai/qurl-connector/pkg/config"
	"github.com/layervai/qurl-connector/pkg/version"
)

// resolveAuditFilePath decides where audit records are written. It prefers the
// operator-chosen path (the QURL_AUDIT_FILE override or the YAML/Docker
// default) and falls back to a user-writable path under the resolved state
// directory when the preferred path's parent cannot be created — the common
// non-root case where the /var/log/layerv default needs root and audit would
// otherwise silently drop to a NopLogger. It returns the chosen path and
// whether a fallback was substituted so the caller can WARN exactly once.
func resolveAuditFilePath(preferred string) (path string, usedFallback bool) {
	preferred = strings.TrimSpace(preferred)
	if preferred == "" {
		preferred = nhpconfig.DefaultAuditFilePath
	}
	if auditDirCreatable(filepath.Dir(preferred)) {
		return preferred, false
	}
	fallback := filepath.Join(agentstate.ResolveDir(""), "audit", filepath.Base(preferred))
	return fallback, true
}

// auditDirCreatable reports whether dir already exists or can be created,
// mirroring the os.MkdirAll that audit.NewJSONLLogger performs at construction.
// It only creates directories the process could create regardless, so it is
// side-effect-safe on success and simply returns false (rather than erroring)
// when the target needs privileges this process lacks.
func auditDirCreatable(dir string) bool {
	return os.MkdirAll(filepath.Clean(dir), 0o755) == nil
}

// initEarlyAuditLogger constructs the audit Logger that catches
// pre-YAML-load native-registration events (whose stable wire names retain
// bootstrap.success/.deny/.error). It honors
// QURL_AUDIT_FILE and falls back to nhpconfig.DefaultAuditFilePath.
// Rotation knobs use the pkg/audit defaults; mirror_slog defaults
// true. The YAML-driven swap (swapAuditLoggerFromYAML) runs after
// nhpconfig.Load returns and supersedes this one for the runtime
// portion of the process — runtime knock/login/proxy/teardown
// entries hit the YAML-configured sink.
//
// Returns NopLogger on disabled-audit (QURL_AUDIT_ENABLED=false) so
// the rest of the code path stays uniform; early registration audit goes
// silent in that case, matching the operator's intent.
func initEarlyAuditLogger(machineID string) (audit.Logger, error) {
	if !auditEnabledFromEnv() {
		return audit.NopLogger{}, nil
	}
	path, usedFallback := resolveAuditFilePath(os.Getenv(nhpconfig.EnvAuditFile))
	if usedFallback {
		slog.Warn("audit: default audit path is not writable by this (non-root) user; writing audit records to a user-writable fallback instead",
			"path", path, "default", nhpconfig.DefaultAuditFilePath)
	}
	return audit.NewJSONLLogger(audit.LoggerConfig{
		FilePath:   path,
		MachineID:  machineID,
		Version:    version.Version,
		MirrorSlog: true,
		// Rotation knobs left at the pkg/audit defaults; the YAML
		// swap below can override.
	})
}

// auditEnabledFromEnv returns false only when QURL_AUDIT_ENABLED is
// set to an explicit off value. Default is true (audit on) — the
// whole point of this PR is wiring the previously-dead package. An
// env-only kill switch exists for operators who want to fully
// silence the audit pipeline during incident triage or compliance-
// scope debugging without rewriting the YAML.
//
// Vocabulary aligned with pkg/config's QURL_ADMIN_ENABLED parser:
// on values {1, true, yes, on}, off values {0, false, no, off},
// case-insensitive + whitespace-trimmed. An empty value falls
// through to the default (audit on) silently — mirrors the
// admin-parser carve-out for the "exported-but-unset" CI shell
// shape (`export QURL_AUDIT_ENABLED` with no value). An unrecognized
// value warns to stderr and falls through to on; a typo'd kill
// switch silently leaving audit on during compliance debugging is
// the foot-gun the loud-warn closes.
func auditEnabledFromEnv() bool {
	raw, ok := os.LookupEnv("QURL_AUDIT_ENABLED")
	if !ok {
		return true
	}
	v := strings.ToLower(strings.TrimSpace(raw))
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	case "":
		// Exported-but-empty (`export QURL_AUDIT_ENABLED`); silent
		// fall-through to default. See QURL_ADMIN_ENABLED parser
		// for the same carve-out rationale.
		return true
	default:
		fmt.Fprintf(os.Stderr,
			"warning: QURL_AUDIT_ENABLED=%q not recognized (use true/false/1/0/yes/no/on/off); falling back to audit enabled (default on)\n",
			raw)
		return true
	}
}

// swapAuditLoggerFromYAML rebuilds the audit Logger using the YAML-
// loaded AuditConfig, closes the current default, and installs the
// new one as the process default. Called once from startFRPFromConfig
// after nhpconfig.Load returns. Early registration audit events have
// already been emitted to the early logger by this point.
//
// On any failure (open error, permission, parent-dir mkdir refusal)
// the function leaves the early-init logger in place and surfaces
// the error to the caller as a non-fatal warning — audit is
// observability and must not break tunnel boot. The caller decides
// how to log the warning (cmd/frpc uses slog).
//
// Calling Close on the swapped-out logger is essential — the
// previous logger owns an open file descriptor and a background
// goroutine; leaking it would keep the early-init file open AND
// double-buffer entries between two sinks for the lifetime of the
// process.
func swapAuditLoggerFromYAML(cfg *nhpconfig.Config, machineID, agentID string) error {
	if cfg == nil {
		return fmt.Errorf("nil config")
	}
	// Env kill switch wins over YAML. Without this short-circuit, an
	// operator who set QURL_AUDIT_ENABLED=false for incident triage
	// gets early registration events suppressed (handled in
	// initEarlyAuditLogger) and then sees runtime audit come back
	// once startFRPFromConfig runs the swap — exactly the opposite of
	// the documented env kill-switch semantic. Check env BEFORE
	// cfg.Audit.Enabled so the env override remains
	// authoritative regardless of YAML settings.
	if !auditEnabledFromEnv() {
		prev := audit.SetDefault(audit.NopLogger{})
		closeAuditLogger(prev)
		return nil
	}
	if cfg.Audit.Enabled != nil && !*cfg.Audit.Enabled {
		// YAML disabled — swap to NopLogger so emit sites stay
		// uniform but bypass file I/O.
		prev := audit.SetDefault(audit.NopLogger{})
		closeAuditLogger(prev)
		return nil
	}
	// MirrorSlog tri-state: after nhpconfig.Load runs applyDefaults
	// (which populates Audit.MirrorSlog with a true pointer when the
	// YAML left it unset), this field is never nil on the production
	// path. The nil guard exists for callers that build *Config
	// directly without going through Load (current callers: the
	// cmd/frpc audit tests). Production path always takes the
	// `*cfg.Audit.MirrorSlog` branch.
	mirror := true
	if cfg.Audit.MirrorSlog != nil {
		mirror = *cfg.Audit.MirrorSlog
	}
	// Route the YAML/default path through the same non-root fallback the early
	// logger used. The fallback is silent here: initEarlyAuditLogger already
	// emitted the single WARN naming the chosen path, and this swap resolves to
	// the same location, so re-warning would only duplicate the message.
	auditPath, _ := resolveAuditFilePath(cfg.Audit.FilePath)
	newLogger, err := audit.NewJSONLLogger(audit.LoggerConfig{
		FilePath:   auditPath,
		MachineID:  machineID,
		Version:    version.Version,
		Actor:      agentID,
		MirrorSlog: mirror,
		BufferSize: cfg.Audit.BufferSize,
		Rotation: audit.RotationConfig{
			MaxSizeMB:  cfg.Audit.MaxSizeMB,
			MaxAgeDays: cfg.Audit.MaxAgeDays,
			MaxBackups: cfg.Audit.MaxBackups,
			Compress:   cfg.Audit.Compress,
		},
	})
	if err != nil {
		return fmt.Errorf("open YAML-configured audit logger: %w", err)
	}
	prev := audit.SetDefault(newLogger)
	closeAuditLogger(prev)
	return nil
}

// closeAuditLogger calls Close on a Logger. Close() error is part of
// the Logger interface so every concrete implementation in pkg/audit
// (JSONLLogger, NopLogger, fakeLogger in tests) satisfies it
// directly — no interface assertion needed. NopLogger.Close is a
// no-op that returns nil; calling it is harmless.
//
// The nil guard exists because audit.SetDefault(nil) is a documented
// way to reset to the NopLogger fallback; callers using closeAuditLogger
// to drain a SetDefault return value would otherwise have to nil-check
// at every call site.
//
// Defense-in-depth note: today's live callers (swapAuditLoggerFromYAML
// + runCmdFunc's deferred close) never pass nil — audit.SetDefault's
// return value is always a non-nil Logger (it coerces a nil install
// to NopLogger via the Default() fallback). The nil guard is dead
// code on those paths but kept so direct test callers that pass
// literal nil don't panic. If a future caller starts threading nil
// intentionally (eg. a "no swap" sentinel), the guard catches it.
//
// Non-nil close errors surface via slog.Warn so a swap-time disk
// failure (rotator's final Flush returns EIO, etc.) is observable
// in the central log shipper. Audit must not break the data plane
// — we never escalate; the close error is observability, not a
// fatal.
//
// Double-close safety: JSONLLogger.Close is guarded by sync.Once
// (see closeOnce in pkg/audit/logger.go), so calling closeAuditLogger
// twice on the same Logger is safe — the second call is a no-op
// that does not re-emit a warning (Once.Do swallows the second
// invocation entirely). This matters at process exit: runCmdFunc's
// `defer _ = audit.Default().Close()` can land on a Logger that
// swapAuditLoggerFromYAML already drained, and the double-close is
// intentionally tolerated.
func closeAuditLogger(l audit.Logger) {
	if l == nil {
		return
	}
	if err := l.Close(); err != nil {
		slog.Warn("audit: close failed during logger swap or shutdown",
			"err", err.Error())
	}
}
