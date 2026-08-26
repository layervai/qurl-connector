package audit

import (
	"io"

	"gopkg.in/natefinch/lumberjack.v2"
)

// Rotation policy defaults. These are the values an operator gets when
// the audit YAML block is present with size/age/backups left zero. The
// defaults target "industry-standard" forensic-grade local audit:
//
//   - DefaultMaxSizeMB (100 MB) — one file fits comfortably in a
//     mid-tier log shipper's batch and a CI rebuild of a year's worth
//     of audit doesn't OOM a small container. The lumberjack default
//     is 100 MB; we re-state it here as the source of truth so a
//     future lumberjack bump can't silently shift the floor.
//   - DefaultMaxAgeDays (90 days) — matches SOC 2 / PCI DSS minimum
//     audit retention (90 days hot / 1 year archived). The hot-tier
//     90-day window is what the local file owns; longer retention is
//     a log-shipper concern.
//   - DefaultMaxBackups (14 files) — at 100 MB each, ~1.4 GB on disk
//     before the oldest is evicted. Pair with daily rotation pressure
//     (size-triggered, not time-triggered) for steady-state ~2-week
//     forensic window even on a bursty event source.
//   - DefaultCompress (true) — gzip the rotated backups. Lumberjack
//     compresses asynchronously after rotation so steady-state log
//     latency is unaffected; the 5-10× compression ratio on JSONL is
//     too large a win to leave on the table by default.
const (
	DefaultMaxSizeMB  = 100
	DefaultMaxAgeDays = 90
	DefaultMaxBackups = 14
	DefaultCompress   = true
)

// RotationConfig configures the size/age/count rotation policy on the
// underlying audit file. Zero values fall through to the Default*
// constants above so a partial YAML block stays valid.
//
// Rotation behavior (lumberjack-implemented):
//   - Size-triggered: when the active file exceeds MaxSizeMB, it is
//     renamed with a timestamp suffix and a new active file is opened.
//   - Age-eviction: rotated backups older than MaxAgeDays are deleted
//     on the next rotation event.
//   - Count-eviction: at most MaxBackups rotated files are retained;
//     the oldest are deleted on the next rotation event.
//   - Compression: rotated backups are gzipped after rename, in a
//     background goroutine, when Compress is true.
//
// Rotation while the audit log is being actively written is safe:
// lumberjack closes the active fd, renames the file atomically (temp +
// rename within the same dir), opens a fresh fd, and continues. The
// JSONLLogger's *bufio.Writer wrapper sees a transparent fd swap and
// keeps appending — no entries are dropped at the rotation seam.
type RotationConfig struct {
	MaxSizeMB  int `yaml:"max_size_mb,omitempty"`
	MaxAgeDays int `yaml:"max_age_days,omitempty"`
	MaxBackups int `yaml:"max_backups,omitempty"`

	// Compress is a tri-state pointer so YAML can distinguish "unset"
	// (operator left the key absent → use DefaultCompress = true)
	// from "explicit false" (operator opted out of gzipping
	// backups). A plain `bool` would collapse those two cases into
	// "false," forcing every operator who omits the key to silently
	// inherit no-compression — the opposite of the intended default.
	//
	// nil ≠ false. Resolution lives in newRotatingWriter:
	//
	//	compress := DefaultCompress      // nil → default (true)
	//	if rc.Compress != nil {
	//	    compress = *rc.Compress      // explicit value wins
	//	}
	Compress *bool `yaml:"compress,omitempty"`
}

// newRotatingWriter constructs a lumberjack-backed io.WriteCloser at
// filePath using the rotation policy in rc. Zero values in rc resolve
// to the Default* constants above. Compress defaults to true when nil
// (the operator did NOT set it) and to the explicit value when set,
// so an operator can opt OUT by writing `compress: false` in YAML
// without paying for gzip on every rotation.
//
// The returned writer is safe for concurrent use (lumberjack serializes
// writes internally), but the JSONLLogger funnels every entry through
// one goroutine anyway — concurrency safety is a defense-in-depth
// property here, not a load-bearing one.
func newRotatingWriter(filePath string, rc RotationConfig) io.WriteCloser {
	maxSize := rc.MaxSizeMB
	if maxSize <= 0 {
		maxSize = DefaultMaxSizeMB
	}
	maxAge := rc.MaxAgeDays
	if maxAge <= 0 {
		maxAge = DefaultMaxAgeDays
	}
	maxBackups := rc.MaxBackups
	if maxBackups <= 0 {
		maxBackups = DefaultMaxBackups
	}
	compress := DefaultCompress
	if rc.Compress != nil {
		compress = *rc.Compress
	}
	return &lumberjack.Logger{
		Filename:   filePath,
		MaxSize:    maxSize,
		MaxAge:     maxAge,
		MaxBackups: maxBackups,
		Compress:   compress,
		// LocalTime stays at its zero value (false) so rotated backups
		// stamp in UTC — matches Entry.Timestamp's UTC contract and
		// keeps cross-host file-name comparisons unambiguous.
		//
		// File permissions: lumberjack v2.2.1 does NOT expose a
		// FileMode field. Its `openNew` defaults to 0o600 (good) but
		// will COPY the existing file's mode if the file already
		// exists (lumberjack.go:218-219), which means whatever mode
		// the file had on the prior process matters. To guarantee
		// 0o600 on every install (incl. fresh-create AND existing-
		// file paths), NewJSONLLogger pre-touches the file at 0o600
		// before handing the path to lumberjack. See
		// preCreateAuditFileAt0600 in logger.go for the rationale —
		// the prior pre-lumberjack implementation used
		// `os.OpenFile(..., 0o600)` explicitly and we MUST preserve
		// that property. Audit logs contain source IPs and session
		// IDs; world-readable would be a real posture regression.
	}
}
