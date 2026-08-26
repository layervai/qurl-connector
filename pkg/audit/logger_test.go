package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func tempFilePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "audit.jsonl")
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	var lines []string
	sc := bufio.NewScanner(f)
	// Increase buffer for large entries.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan %s: %v", path, err)
	}
	return lines
}

func TestJSONLLogger_SingleEntry(t *testing.T) {
	path := tempFilePath(t)
	l, err := NewJSONLLogger(LoggerConfig{
		FilePath:  path,
		MachineID: "m-001",
		Version:   "v1.0.0",
	})
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}

	l.Log(Entry{
		Event:    "proxy.access",
		Action:   ActionAllow,
		SourceIP: "10.0.0.1",
	})

	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	lines := readLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}

	var e Entry
	if err := json.Unmarshal([]byte(lines[0]), &e); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if e.Event != "proxy.access" {
		t.Errorf("event = %q, want %q", e.Event, "proxy.access")
	}
	if e.Action != ActionAllow {
		t.Errorf("action = %q, want %q", e.Action, ActionAllow)
	}
	if e.SourceIP != "10.0.0.1" {
		t.Errorf("source_ip = %q, want %q", e.SourceIP, "10.0.0.1")
	}
	if e.MachineID != "m-001" {
		t.Errorf("machine_id = %q, want %q", e.MachineID, "m-001")
	}
	if e.ProxyVersion != "v1.0.0" {
		t.Errorf("proxy_version = %q, want %q", e.ProxyVersion, "v1.0.0")
	}
	if e.Timestamp.IsZero() {
		t.Error("timestamp is zero")
	}
}

func TestJSONLLogger_MultipleEntries(t *testing.T) {
	path := tempFilePath(t)
	l, err := NewJSONLLogger(LoggerConfig{
		FilePath:  path,
		MachineID: "m-multi",
		Version:   "v2.0.0",
	})
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}

	const perGoroutine = 10
	const goroutines = 10
	const total = perGoroutine * goroutines

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				l.Log(Entry{
					Event:    "proxy.access",
					Action:   ActionAllow,
					SourceIP: "10.0.0.1",
				})
			}
		}()
	}
	wg.Wait()

	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	lines := readLines(t, path)
	if len(lines) != total {
		t.Fatalf("expected %d lines, got %d", total, len(lines))
	}

	for i, line := range lines {
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Errorf("line %d: unmarshal: %v", i, err)
		}
	}
}

func TestJSONLLogger_StampsMachineFields(t *testing.T) {
	path := tempFilePath(t)
	l, err := NewJSONLLogger(LoggerConfig{
		FilePath:  path,
		MachineID: "stamped-id",
		Version:   "v3.0.0",
		Actor:     "agent-actor-001",
	})
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}

	// Log entry with empty machine fields — logger must stamp them.
	l.Log(Entry{
		Event:    "proxy.access",
		Action:   ActionDenyExpired,
		SourceIP: "192.168.1.1",
	})

	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	lines := readLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}

	var e Entry
	if err := json.Unmarshal([]byte(lines[0]), &e); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if e.MachineID != "stamped-id" {
		t.Errorf("machine_id = %q, want %q", e.MachineID, "stamped-id")
	}
	if e.ProxyVersion != "v3.0.0" {
		t.Errorf("proxy_version = %q, want %q", e.ProxyVersion, "v3.0.0")
	}
	if e.Actor != "agent-actor-001" {
		t.Errorf("actor = %q, want %q", e.Actor, "agent-actor-001")
	}
}

func TestJSONLLogger_DrainOnClose(t *testing.T) {
	path := tempFilePath(t)
	l, err := NewJSONLLogger(LoggerConfig{
		FilePath:  path,
		MachineID: "drain",
		Version:   "v1.0.0",
	})
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}

	const total = 50
	for i := 0; i < total; i++ {
		l.Log(Entry{
			Event:    "proxy.access",
			Action:   ActionAllow,
			SourceIP: "10.0.0.1",
		})
	}

	// Close immediately — must drain all buffered entries.
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	lines := readLines(t, path)
	if len(lines) != total {
		t.Fatalf("expected %d lines, got %d", total, len(lines))
	}
}

func TestJSONLLogger_TimestampFormat(t *testing.T) {
	path := tempFilePath(t)
	l, err := NewJSONLLogger(LoggerConfig{
		FilePath:  path,
		MachineID: "ts",
		Version:   "v1.0.0",
	})
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}

	before := time.Now().UTC()
	l.Log(Entry{
		Event:    "proxy.access",
		Action:   ActionAllow,
		SourceIP: "10.0.0.1",
	})
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	after := time.Now().UTC()

	lines := readLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}

	// Extract raw ts value from JSON.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(lines[0]), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var tsStr string
	if err := json.Unmarshal(raw["ts"], &tsStr); err != nil {
		t.Fatalf("unmarshal ts: %v", err)
	}

	// Must parse as RFC3339Nano.
	ts, err := time.Parse(time.RFC3339Nano, tsStr)
	if err != nil {
		t.Fatalf("parse ts %q as RFC3339Nano: %v", tsStr, err)
	}

	if ts.Location() != time.UTC {
		t.Errorf("timestamp location = %v, want UTC", ts.Location())
	}
	if ts.Before(before) || ts.After(after) {
		t.Errorf("timestamp %v not between %v and %v", ts, before, after)
	}
}

func TestJSONLLogger_CreatesParentDirs(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "a", "b", "c", "audit.jsonl")

	l, err := NewJSONLLogger(LoggerConfig{
		FilePath:  path,
		MachineID: "dirs",
		Version:   "v1.0.0",
	})
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}

	l.Log(Entry{
		Event:    "proxy.access",
		Action:   ActionAllow,
		SourceIP: "10.0.0.1",
	})

	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file not created at %s: %v", path, err)
	}

	lines := readLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}
}

func TestNopLogger_Safe(t *testing.T) {
	var l NopLogger
	// Must not panic.
	l.Log(Entry{Event: "test", Action: ActionAllow, SourceIP: "1.2.3.4"})
	if err := l.Close(); err != nil {
		t.Fatalf("NopLogger.Close returned error: %v", err)
	}
}

// TestJSONLLogger_FileModeIs0600 pins the cr-round-1 🔴 fix: the
// active audit file MUST be created at 0o600 (owner-only). Audit
// entries include source IPs and session IDs; world-readable would
// be a posture regression vs. the pre-lumberjack implementation
// that used `os.OpenFile(..., 0o600)` explicitly. Lumberjack v2.2.1
// doesn't expose a FileMode knob, so pkg/audit pre-touches the file
// at 0o600 — this test guarantees the contract regardless of
// lumberjack internals.
func TestJSONLLogger_FileModeIs0600(t *testing.T) {
	path := tempFilePath(t)
	l, err := NewJSONLLogger(LoggerConfig{
		FilePath:  path,
		MachineID: "perms",
		Version:   "v1.0.0",
	})
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	l.Log(Entry{Event: EventBootstrapSuccess, Outcome: OutcomeSuccess})
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	got := info.Mode().Perm()
	if got != 0o600 {
		t.Errorf("audit file mode = %#o, want 0o600 (owner-only; audit entries contain source IPs and session IDs)", got)
	}
}

// TestJSONLLogger_PreExistingFileMode0600 covers the upgrade-path
// branch: an audit file that already exists at the configured path
// MUST be re-chmodded to 0o600 even if it landed there with a
// drifted mode. Without this, a hypothetical 0o644 file from a
// prior install (or operator-side `chmod 644`) would survive across
// the lumberjack transition silently.
func TestJSONLLogger_PreExistingFileMode0600(t *testing.T) {
	path := tempFilePath(t)
	// Seed the file at 0o644 (the mode a hypothetical lumberjack
	// default would have granted had we not pre-touched it).
	if err := os.WriteFile(path, []byte("pre-existing junk\n"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	l, err := NewJSONLLogger(LoggerConfig{
		FilePath:  path,
		MachineID: "perms-upgrade",
		Version:   "v1.0.0",
	})
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("pre-existing file mode after NewJSONLLogger = %#o, want 0o600 (chmod-on-upgrade should converge)", got)
	}
}

// TestJSONLLogger_TimestampAlwaysOverwritten pins the cr-round-1 🟡
// fix: Log() unconditionally overwrites Entry.Timestamp with
// time.Now().UTC() even when the caller supplied one. A caller-set
// timestamp would open a "stale timestamp from a retry queue"
// failure mode that defeats the forensic-grade guarantee of
// `ts == wall-clock moment Log was called`.
func TestJSONLLogger_TimestampAlwaysOverwritten(t *testing.T) {
	path := tempFilePath(t)
	l, err := NewJSONLLogger(LoggerConfig{
		FilePath:  path,
		MachineID: "ts-overwrite",
		Version:   "v1.0.0",
	})
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	stale := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	before := time.Now().UTC()
	l.Log(Entry{
		Event:     EventBootstrapSuccess,
		Outcome:   OutcomeSuccess,
		Timestamp: stale,
	})
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	after := time.Now().UTC()

	lines := readLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}
	var e Entry
	if err := json.Unmarshal([]byte(lines[0]), &e); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if e.Timestamp.Equal(stale) {
		t.Errorf("Log() preserved caller-supplied stale timestamp %v — must always stamp", stale)
	}
	if e.Timestamp.Before(before) || e.Timestamp.After(after) {
		t.Errorf("Log() stamped timestamp %v outside [%v, %v]", e.Timestamp, before, after)
	}
}

// TestJSONLLogger_LogAfterCloseDoesNotPanic pins the cr-round-2 🟠
// fix: Log() recovers the send-on-closed-channel panic that the
// audit-logger swap path could otherwise race into. The race
// sequence (cmd/frpc/audit.go's swapAuditLoggerFromYAML closes the
// previous logger while an emit goroutine still holds the pre-swap
// Logger pointer): goroutine A loads audit.Default() → L1; swap
// fires close(L1.ch); A calls L1.Log(...) → would panic without
// the recover guard. Drop counter must increment so the entry is
// accounted, not silently lost.
func TestJSONLLogger_LogAfterCloseDoesNotPanic(t *testing.T) {
	path := tempFilePath(t)
	l, err := NewJSONLLogger(LoggerConfig{
		FilePath:  path,
		MachineID: "close-race",
		Version:   "v1.0.0",
	})
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	// Pre-Close drop counter baseline.
	pre := l.DroppedCount()
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// Post-Close Log must NOT panic — the recover guard catches
	// the closed-channel send and increments dropped instead.
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Log() panicked after Close: %v (recover guard missing or broken)", r)
		}
	}()
	l.Log(Entry{Event: EventBootstrapSuccess, Outcome: OutcomeSuccess})
	if got := l.DroppedCount(); got <= pre {
		t.Errorf("dropped counter did not advance after closed-channel Log: pre=%d post=%d", pre, got)
	}
}

// TestJSONLLogger_NewFieldsRoundTrip verifies the new Entry fields
// (Outcome, Actor, TraceID, Reason) survive the encode → file → decode
// cycle so cross-repo dashboard schemas stay aligned with the emit
// sites.
func TestJSONLLogger_NewFieldsRoundTrip(t *testing.T) {
	path := tempFilePath(t)
	l, err := NewJSONLLogger(LoggerConfig{
		FilePath:  path,
		MachineID: "rt",
		Version:   "v9.9.9",
	})
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}

	in := Entry{
		Event:      EventLoginDeny,
		Outcome:    OutcomeDeny,
		Actor:      "agent-7f",
		TraceID:    "run_abc123",
		RunID:      "0123456789abcdef",
		Reason:     "knock_token_invalid",
		ResourceID: "r_xyz",
		SourceIP:   "10.0.0.1",
		Error:      "login to the server failed: knock_invalid: knock token rejected",
	}
	l.Log(in)
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	lines := readLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}
	var out Entry
	if err := json.Unmarshal([]byte(lines[0]), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Event != in.Event {
		t.Errorf("event = %q, want %q", out.Event, in.Event)
	}
	if out.Outcome != in.Outcome {
		t.Errorf("outcome = %q, want %q", out.Outcome, in.Outcome)
	}
	if out.Actor != in.Actor {
		t.Errorf("actor = %q, want %q", out.Actor, in.Actor)
	}
	if out.TraceID != in.TraceID {
		t.Errorf("trace_id = %q, want %q", out.TraceID, in.TraceID)
	}
	if out.RunID != in.RunID {
		t.Errorf("run_id = %q, want %q", out.RunID, in.RunID)
	}
	if out.Reason != in.Reason {
		t.Errorf("reason = %q, want %q", out.Reason, in.Reason)
	}
	if out.ResourceID != in.ResourceID {
		t.Errorf("resource_id = %q, want %q", out.ResourceID, in.ResourceID)
	}
	if out.Error != in.Error {
		t.Errorf("error = %q, want %q", out.Error, in.Error)
	}
}

// captureSlog installs a buffered JSON slog handler for the duration
// of t and returns a *bytes.Buffer that holds every emitted record.
// The previous default is restored on test cleanup so parallel-package
// runs don't see leakage.
func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	prev := slog.Default()
	buf := &bytes.Buffer{}
	h := slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() {
		slog.SetDefault(prev)
	})
	return buf
}

// TestJSONLLogger_MirrorSlog_Enabled asserts that each entry written
// to the file also lands in slog at INFO level when MirrorSlog is
// true.
func TestJSONLLogger_MirrorSlog_Enabled(t *testing.T) {
	slogBuf := captureSlog(t)

	path := tempFilePath(t)
	l, err := NewJSONLLogger(LoggerConfig{
		FilePath:   path,
		MachineID:  "mirror",
		Version:    "v1.0.0",
		MirrorSlog: true,
	})
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}

	entries := []Entry{
		{Event: EventBootstrapSuccess, Outcome: OutcomeSuccess, Actor: "a1"},
		{Event: EventKnockSuccess, Outcome: OutcomeSuccess, ResourceID: "r_xyz"},
		{Event: EventTeardown, Outcome: OutcomeSuccess, ResourceID: "r_xyz"},
	}
	for _, e := range entries {
		l.Log(e)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// File has N entries.
	lines := readLines(t, path)
	if len(lines) != len(entries) {
		t.Fatalf("file lines = %d, want %d", len(lines), len(entries))
	}

	// slog buffer has the same N entries (one per Log call) — events
	// land as the slog msg field, in order.
	slogLines := splitNonEmpty(slogBuf.String())
	if len(slogLines) != len(entries) {
		t.Fatalf("slog lines = %d, want %d (buf=%q)", len(slogLines), len(entries), slogBuf.String())
	}
	for i, line := range slogLines {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("slog line %d unmarshal: %v (%q)", i, err, line)
		}
		if rec["msg"] != entries[i].Event {
			t.Errorf("slog line %d msg = %v, want %q", i, rec["msg"], entries[i].Event)
		}
		if rec["level"] != "INFO" {
			t.Errorf("slog line %d level = %v, want INFO", i, rec["level"])
		}
		if string(entries[i].Outcome) != "" && rec["outcome"] != string(entries[i].Outcome) {
			t.Errorf("slog line %d outcome = %v, want %q", i, rec["outcome"], entries[i].Outcome)
		}
		// "ts" attr present and parseable as RFC3339Nano: this is the
		// Log()-call time, distinct from the slog handler's own
		// record-time. Central log shippers MUST key on this attr to
		// stay correlated with the file's "ts" field; the handler's
		// record-time drifts with encoder-goroutine drain latency.
		// See mirrorToSlog godoc for the rationale.
		tsRaw, ok := rec["ts"].(string)
		if !ok {
			t.Errorf("slog line %d missing ts attr or wrong type: %v", i, rec["ts"])
			continue
		}
		if _, err := time.Parse(time.RFC3339Nano, tsRaw); err != nil {
			t.Errorf("slog line %d ts %q not RFC3339Nano: %v", i, tsRaw, err)
		}
	}
}

// TestJSONLLogger_MirrorSlog_Disabled asserts that when MirrorSlog is
// false the slog default sees no audit records.
func TestJSONLLogger_MirrorSlog_Disabled(t *testing.T) {
	slogBuf := captureSlog(t)

	path := tempFilePath(t)
	l, err := NewJSONLLogger(LoggerConfig{
		FilePath:  path,
		MachineID: "no-mirror",
		Version:   "v1.0.0",
		// MirrorSlog left at zero-value (false).
	})
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}

	l.Log(Entry{Event: EventBootstrapSuccess, Outcome: OutcomeSuccess})
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if got := strings.TrimSpace(slogBuf.String()); got != "" {
		t.Errorf("slog buffer non-empty with MirrorSlog=false: %q", got)
	}
}

// TestJSONLLogger_RotationTriggersOnSize writes entries large enough
// to force lumberjack to rotate the active file. The active file
// should remain present and small post-rotation; at least one rotated
// backup should exist alongside it.
func TestJSONLLogger_RotationTriggersOnSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	// MaxSizeMB=1 (lumberjack's minimum-meaningful) + Compress=false
	// so the test doesn't depend on gzip timing. MaxBackups=5 leaves
	// room for the rotated files to land.
	compress := false
	l, err := NewJSONLLogger(LoggerConfig{
		FilePath:  path,
		MachineID: "rot",
		Version:   "v1.0.0",
		Rotation: RotationConfig{
			MaxSizeMB:  1,
			MaxAgeDays: 7,
			MaxBackups: 5,
			Compress:   &compress,
		},
		// Generous channel buffer so the loop below doesn't drop.
		BufferSize: 16 * 1024,
	})
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}

	// One entry is ~ a few hundred bytes; ~10k entries comfortably
	// pushes past the 1 MB rotation threshold. Pad the payload with a
	// large Error string so the per-entry size is predictable.
	payload := strings.Repeat("x", 512)
	for i := 0; i < 5000; i++ {
		l.Log(Entry{
			Event:   EventLoginSuccess,
			Outcome: OutcomeSuccess,
			Error:   payload,
		})
	}
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// At least one rotated file alongside the active one.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	var active, rotated int
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if name == "audit.jsonl" {
			active++
			continue
		}
		// Lumberjack rotated files look like
		// "audit-2026-05-26T12-34-56.789.jsonl" — same prefix +
		// timestamp + same extension.
		if strings.HasPrefix(name, "audit-") && strings.HasSuffix(name, ".jsonl") {
			rotated++
		}
	}
	if active != 1 {
		t.Fatalf("expected 1 active file, found %d (entries=%v)", active, entries)
	}
	if rotated < 1 {
		t.Fatalf("expected at least 1 rotated file, found %d (entries=%v)", rotated, entries)
	}

	// Permissions sweep: BOTH active and every rotated backup must
	// be 0o600. Active is set by preCreateAuditFileAt0600 + chmod
	// in NewJSONLLogger; rotated backups inherit the mode via
	// os.Rename (same inode), which lumberjack v2.2.1's openNew uses
	// to move the active aside before opening a fresh active. A
	// future lumberjack bump that switched to copy-rename (or to
	// using a different default mode for rotated files) would
	// silently regress the 0o600 contract for backups; this sweep
	// catches that regression. See preCreateAuditFileAt0600 for
	// the active-file enforcement rationale.
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		full := filepath.Join(dir, e.Name())
		info, err := os.Stat(full)
		if err != nil {
			t.Fatalf("stat %s: %v", full, err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("file %q mode = %#o, want 0o600 (audit files carry source IPs and session IDs — owner-only)", e.Name(), perm)
		}
	}
}

// TestJSONLLogger_RotationDefaultsApplyWhenZero pins the rotation-
// defaults behavior: an empty RotationConfig must not crash and must
// produce a writable active file.
func TestJSONLLogger_RotationDefaultsApplyWhenZero(t *testing.T) {
	path := tempFilePath(t)
	l, err := NewJSONLLogger(LoggerConfig{
		FilePath:  path,
		MachineID: "rot-default",
		Version:   "v1.0.0",
		// RotationConfig left zero-valued; defaults must apply.
	})
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	l.Log(Entry{Event: EventBootstrapSuccess, Outcome: OutcomeSuccess})
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	lines := readLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}
}

// TestJSONLLogger_DropCounterIncrements forces buffer-full drops by
// using a 1-element buffer and an in-flight rotator that blocks on a
// slow writer. The dropped counter must move past zero.
func TestJSONLLogger_DropCounterIncrements(t *testing.T) {
	path := tempFilePath(t)
	l, err := NewJSONLLogger(LoggerConfig{
		FilePath:   path,
		MachineID:  "drops",
		Version:    "v1.0.0",
		BufferSize: 1,
	})
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}

	// The drain goroutine consumes from the channel as fast as it can
	// write. To force backpressure we spin a tight Log loop from many
	// goroutines and count drops; the 1-slot channel guarantees most
	// Log calls during the burst land in the default branch.
	const goroutines = 32
	const perGoroutine = 1000
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				l.Log(Entry{Event: EventLoginSuccess, Outcome: OutcomeSuccess})
			}
		}()
	}
	wg.Wait()

	// Stash the drop count before Close drains; Close itself doesn't
	// move the counter (it only flushes already-queued entries).
	dropsAtBurstEnd := l.DroppedCount()
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// At the rates used above the writer cannot keep up with a 1-slot
	// channel; this assertion is empirically robust. If it ever flakes
	// on a very fast runner, raise goroutines/perGoroutine rather than
	// weakening the assertion — the counter is the whole point of the
	// observability surface.
	if dropsAtBurstEnd == 0 {
		t.Fatalf("expected drops > 0 with 1-slot buffer + %d goroutines × %d logs", goroutines, perGoroutine)
	}
}

// fakeLogger is a minimal in-memory Logger for testing the
// Default/SetDefault contract without spinning up a JSONLLogger.
type fakeLogger struct {
	mu      sync.Mutex
	entries []Entry
}

func (f *fakeLogger) Log(e Entry) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries = append(f.entries, e)
}

func (f *fakeLogger) Close() error { return nil }

func (f *fakeLogger) snapshot() []Entry {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Entry, len(f.entries))
	copy(out, f.entries)
	return out
}

func TestDefault_FallsBackToNopWhenUnset(t *testing.T) {
	// Defensive: reset whatever a previous test left installed.
	prev := SetDefault(nil)
	t.Cleanup(func() { SetDefault(prev) })

	// Must not panic.
	Default().Log(Entry{Event: EventBootstrapSuccess})
	if err := Default().Close(); err != nil {
		t.Fatalf("Default().Close: %v", err)
	}
}

func TestSetDefault_InstallsAndRestores(t *testing.T) {
	f := &fakeLogger{}
	prev := SetDefault(f)
	t.Cleanup(func() { SetDefault(prev) })

	Default().Log(Entry{Event: EventKnockSuccess, Outcome: OutcomeSuccess})
	Default().Log(Entry{Event: EventTeardown, Outcome: OutcomeSuccess})

	got := f.snapshot()
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2", len(got))
	}
	if got[0].Event != EventKnockSuccess {
		t.Errorf("entry[0].Event = %q, want %q", got[0].Event, EventKnockSuccess)
	}
	if got[1].Event != EventTeardown {
		t.Errorf("entry[1].Event = %q, want %q", got[1].Event, EventTeardown)
	}
}

// splitNonEmpty splits s on "\n" and drops any empty trailing element
// (slog.JSONHandler emits one record per line with a trailing newline,
// so strings.Split produces N+1 elements where the last is empty).
func splitNonEmpty(s string) []string {
	parts := strings.Split(s, "\n")
	out := parts[:0]
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			out = append(out, p)
		}
	}
	return out
}
