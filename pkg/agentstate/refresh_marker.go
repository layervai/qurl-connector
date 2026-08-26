package agentstate

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/layervai/qurl-connector/internal/pinnedfs"
)

// RefreshMarkerFile is the state-dir filename that records a pending
// "the persisted Hub assignment may be stale; force one authenticated
// assignment refresh on the next warm restart" request. It is written by the
// managed runtime after its consecutive-knock-failure budget is exhausted and
// consumed by automatic assignment recovery, which asks the Hub for a
// replacement assignment.
//
// It is not an identity envelope: its presence says nothing about whether a
// native identity or device credential was ever persisted, and a directory
// holding only this file has no identity to orphan. Mode 0644 (not 0600)
// because it carries no secret — just a self-heal breadcrumb an operator may
// inspect from the host-mounted state directory.
const RefreshMarkerFile = "registration_refresh.json"

// ErrInvalidRefreshMarker distinguishes a corrupt marker shape that the
// native warm-open path may safely log and remove from a real filesystem I/O
// fault. A transient read/stat fault must not erase the persisted retry
// schedule and reopen the Hub-refresh episode at its initial cadence.
var ErrInvalidRefreshMarker = errors.New("invalid assignment refresh marker")

// refreshMarkerFileMaxBytes caps the marker read. The marker is a tiny JSON
// object; the cap defends the warm-restart read against a corrupt or
// accidentally-grown file being pulled into memory. The reader rejects
// symlinks and non-regular files, compares the opened descriptor with the
// no-follow directory entry, and still uses a LimitReader after the size gate.
// A stale over-cap file fails closed as corrupt and the warm-open side logs and
// clears it through the same retained namespace.
const refreshMarkerFileMaxBytes = 4 << 10 // 4 KiB
const refreshMarkerVersion = 2
const refreshMarkerReasonMaxBytes = 256
const refreshRetryInitial = 5 * time.Second
const refreshRetryMaximum = 5 * time.Minute

// RefreshMarker is the durable automatic-recovery schedule for one sustained
// native-assignment failure episode. Every Hub refresh attempt advances a
// persisted exponential backoff with jitter before network I/O starts, so a
// crash cannot reset the retry cadence. A confirmed healthy NHP/FRP cycle
// clears the marker; ordinary refresh failures never require operator action.
type RefreshMarker struct {
	// Version selects the closed marker schema.
	Version int `json:"version"`

	// Reason is a short, human-readable tag for why the refresh was
	// requested (e.g. the sustained-knock-failure cause). Operator-facing
	// only; the self-heal logic does not key off Reason.
	Reason string `json:"reason,omitempty"`

	AttemptCount         uint32 `json:"attempt_count"`
	StartedAtUnix        int64  `json:"started_at_unix"`
	LastAttemptUnixMilli int64  `json:"last_attempt_unix_milli"`
	NextAttemptUnixMilli int64  `json:"next_attempt_unix_milli"`
}

func withRefreshMarkerNamespace(dir string, fn func(*pinnedfs.Directory) error) (retErr error) {
	namespace, err := pinnedfs.EnsurePrivate(ResolveDir(dir), dirMode)
	if err != nil {
		return fmt.Errorf("open registration refresh marker namespace: %w", err)
	}
	defer func() { retErr = errors.Join(retErr, namespace.Close()) }()
	return fn(namespace)
}

// LoadRegistrationRefreshMarker reads the registration-refresh marker from
// dir (empty → ResolveDir). It returns (marker, true, nil) when a
// well-formed marker is present, (zero, false, nil) when absent, and
// (zero, false, err) only for a real I/O fault or a corrupt/oversized
// marker.
//
// A corrupt marker is surfaced as an error rather than silently treated as
// "absent": the native warm-open caller logs it, clears it, and proceeds on
// the ordinary persisted-assignment path (fail-safe — a torn self-heal
// breadcrumb must not itself wedge startup), but swallowing it here would hide
// the corruption from that log entirely.
func LoadRegistrationRefreshMarker(dir string) (RefreshMarker, bool, error) {
	var marker RefreshMarker
	var present bool
	err := withRefreshMarkerNamespace(dir, func(namespace *pinnedfs.Directory) error {
		var err error
		marker, present, err = loadRegistrationRefreshMarker(namespace)
		return err
	})
	return marker, present, err
}

var closeRefreshMarkerFile = func(file *os.File) error { return file.Close() }
var removeRefreshMarkerTemp = func(namespace *pinnedfs.Directory, name string) error {
	return namespace.Remove(name)
}
var syncRefreshMarkerNamespace = func(namespace *pinnedfs.Directory) error {
	return namespace.Sync()
}
var beforeRefreshMarkerPostReadValidation = func(*pinnedfs.Directory) {}
var beforeRefreshMarkerTempValidation = func(*pinnedfs.Directory, string) {}

func loadRegistrationRefreshMarker(namespace *pinnedfs.Directory) (marker RefreshMarker, present bool, retErr error) {
	path := filepath.Join(namespace.Path(), RefreshMarkerFile)
	entry, err := namespace.Lstat(RefreshMarkerFile)
	if err != nil {
		if pinnedfs.IsNotExist(err) {
			return RefreshMarker{}, false, nil
		}
		return RefreshMarker{}, false, fmt.Errorf("stat registration refresh marker %s: %w", path, err)
	}
	if entry.Mode()&os.ModeSymlink != 0 || !entry.Mode().IsRegular() {
		return RefreshMarker{}, false, fmt.Errorf("%w: %s must be a non-symlink regular file", ErrInvalidRefreshMarker, path)
	}
	file, err := namespace.OpenFile(RefreshMarkerFile, os.O_RDONLY|pinnedfs.SafeOpenFlags(), 0)
	if err != nil {
		if pinnedfs.IsNotExist(err) {
			return RefreshMarker{}, false, nil
		}
		return RefreshMarker{}, false, fmt.Errorf("open registration refresh marker %s: %w", path, err)
	}
	defer func() {
		retErr = errors.Join(retErr, closeRefreshMarkerFile(file))
		if retErr != nil {
			marker = RefreshMarker{}
			present = false
		}
	}()
	info, err := pinnedfs.ValidateRegularFile(namespace, RefreshMarkerFile, file, "registration refresh marker", pubMode)
	if err != nil {
		return RefreshMarker{}, false, fmt.Errorf("%w: %s: %w", ErrInvalidRefreshMarker, path, err)
	}
	if info.Size() <= 0 || info.Size() > refreshMarkerFileMaxBytes {
		return RefreshMarker{}, false, fmt.Errorf("%w: %s is %d bytes, exceeds %d-byte cap", ErrInvalidRefreshMarker, path, info.Size(), refreshMarkerFileMaxBytes)
	}
	raw, err := io.ReadAll(io.LimitReader(file, refreshMarkerFileMaxBytes+1))
	if err != nil {
		return RefreshMarker{}, false, fmt.Errorf("read registration refresh marker %s: %w", path, err)
	}
	if len(raw) > refreshMarkerFileMaxBytes {
		return RefreshMarker{}, false, fmt.Errorf("%w: %s exceeds %d-byte cap", ErrInvalidRefreshMarker, path, refreshMarkerFileMaxBytes)
	}
	beforeRefreshMarkerPostReadValidation(namespace)
	if _, err := pinnedfs.ValidateRegularFile(namespace, RefreshMarkerFile, file, "registration refresh marker after read", pubMode); err != nil {
		return RefreshMarker{}, false, fmt.Errorf("%w: %s: %w", ErrInvalidRefreshMarker, path, err)
	}
	m, err := decodeRefreshMarker(raw)
	if err != nil {
		return RefreshMarker{}, false, fmt.Errorf("%w: decode %s: %w", ErrInvalidRefreshMarker, path, err)
	}
	if err := namespace.ValidateCurrent(); err != nil {
		return RefreshMarker{}, false, fmt.Errorf("revalidate registration refresh marker namespace: %w", err)
	}
	return m, true, nil
}

func decodeRefreshMarker(raw []byte) (RefreshMarker, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil {
		return RefreshMarker{}, err
	}
	if token != json.Delim('{') {
		return RefreshMarker{}, errors.New("registration refresh marker must be a JSON object")
	}
	var marker RefreshMarker
	seen := make(map[string]struct{}, 7)
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return RefreshMarker{}, err
		}
		key, ok := keyToken.(string)
		if !ok {
			return RefreshMarker{}, errors.New("registration refresh marker key is not a string")
		}
		if _, duplicate := seen[key]; duplicate {
			return RefreshMarker{}, fmt.Errorf("duplicate registration refresh marker field %q", key)
		}
		seen[key] = struct{}{}
		switch key {
		case "version":
			err = decoder.Decode(&marker.Version)
		case "reason":
			err = decoder.Decode(&marker.Reason)
		case "attempt_count":
			err = decoder.Decode(&marker.AttemptCount)
		case "started_at_unix":
			err = decoder.Decode(&marker.StartedAtUnix)
		case "last_attempt_unix_milli":
			err = decoder.Decode(&marker.LastAttemptUnixMilli)
		case "next_attempt_unix_milli":
			err = decoder.Decode(&marker.NextAttemptUnixMilli)
		default:
			return RefreshMarker{}, fmt.Errorf("unknown registration refresh marker field %q", key)
		}
		if err != nil {
			return RefreshMarker{}, err
		}
	}
	closing, err := decoder.Token()
	if err != nil {
		return RefreshMarker{}, err
	}
	if closing != json.Delim('}') {
		return RefreshMarker{}, errors.New("registration refresh marker object did not close")
	}
	if err := rejectTrailingJSON(decoder); err != nil {
		return RefreshMarker{}, err
	}
	for _, required := range []string{"version", "attempt_count", "started_at_unix", "last_attempt_unix_milli", "next_attempt_unix_milli"} {
		if _, ok := seen[required]; !ok {
			return RefreshMarker{}, fmt.Errorf("registration refresh marker is missing required field %q", required)
		}
	}
	if marker.Version != refreshMarkerVersion {
		return RefreshMarker{}, fmt.Errorf("unsupported registration refresh marker version %d", marker.Version)
	}
	if marker.StartedAtUnix <= 0 {
		return RefreshMarker{}, errors.New("registration refresh marker started_at_unix must be positive")
	}
	if marker.AttemptCount == 0 {
		if marker.LastAttemptUnixMilli != 0 || marker.NextAttemptUnixMilli != 0 {
			return RefreshMarker{}, errors.New("unattempted registration refresh marker must have zero last/next attempt")
		}
	} else if marker.LastAttemptUnixMilli <= 0 || marker.NextAttemptUnixMilli < marker.LastAttemptUnixMilli || marker.LastAttemptUnixMilli < marker.StartedAtUnix*1000 {
		return RefreshMarker{}, errors.New("attempted registration refresh marker has an invalid retry schedule")
	}
	if invalidRefreshMarkerReason(marker.Reason) ||
		strings.TrimSpace(marker.Reason) != marker.Reason {
		return RefreshMarker{}, fmt.Errorf("registration refresh marker reason must be canonical UTF-8 without control characters and at most %d bytes", refreshMarkerReasonMaxBytes)
	}
	return marker, nil
}

// invalidRefreshMarkerReason reports whether reason carries bytes that are
// hostile to durable storage: invalid UTF-8, over the byte cap, or any control
// character. It is the shared core of the read (decodeRefreshMarker) and write
// (requestRegistrationRefresh) validation; each caller layers its own
// canonical-form check (the read path additionally rejects untrimmed
// whitespace) and supplies its own error text.
func invalidRefreshMarkerReason(reason string) bool {
	return !utf8.ValidString(reason) ||
		len(reason) > refreshMarkerReasonMaxBytes ||
		strings.IndexFunc(reason, unicode.IsControl) >= 0
}

// RequestRegistrationRefresh records that sustained knock failures require an
// automatic Hub assignment refresh. It is episode-idempotent: an existing
// marker, including its attempt count and next-at time, is left unchanged.
// Only a confirmed healthy cycle ends the episode.
//
// reason is a short operator-facing tag (the knock-failure cause). Marker
// creation failures are returned so the caller can log them; they are not
// fatal — a connector that cannot write the breadcrumb simply loses the
// self-heal on that restart and falls back to today's behavior.
func RequestRegistrationRefresh(dir, reason string) error {
	return withRefreshMarkerNamespace(dir, func(namespace *pinnedfs.Directory) error {
		return requestRegistrationRefresh(namespace, reason)
	})
}

func requestRegistrationRefresh(namespace *pinnedfs.Directory, reason string) error {
	// Presence-gated, NOT decode-gated: if a marker file exists AT ALL —
	// well-formed, corrupt, or momentarily unreadable — an episode is already
	// open (or being cleaned up by the consume side), so arming is a no-op and
	// we leave the file untouched. Keying off no-follow Lstat presence rather than a
	// successful decode is deliberate: a transient stat/read fault (EACCES flap,
	// EIO, NFS hiccup) on an existing marker must NOT fall through to an
	// overwrite that resets its retry schedule. A genuinely corrupt marker is the
	// native warm-open side's job to log and clear; the set side never needs to
	// rewrite it. Lstat (not Stat) means a
	// dangling marker symlink also counts as "present" and is left alone.
	path := filepath.Join(namespace.Path(), RefreshMarkerFile)
	if _, err := namespace.Lstat(RefreshMarkerFile); err == nil {
		return nil
	} else if !pinnedfs.IsNotExist(err) {
		// A non-ENOENT lstat fault means we cannot confirm the marker is absent.
		// Fail safe: do NOT overwrite an existing marker's retry schedule.
		// Surface the fault so the caller logs it; losing this one arming is
		// harmless (a later budget exit retries).
		return fmt.Errorf("lstat registration refresh marker %s: %w", path, err)
	}
	// No marker file present means a fresh recovery episode.
	reason = strings.TrimSpace(reason)
	if invalidRefreshMarkerReason(reason) {
		return fmt.Errorf("registration refresh reason must be valid UTF-8 without control characters and at most %d bytes", refreshMarkerReasonMaxBytes)
	}
	m := RefreshMarker{
		Version:       refreshMarkerVersion,
		Reason:        reason,
		StartedAtUnix: time.Now().Unix(),
	}
	return writeRefreshMarker(namespace, m)
}

// MarkRegistrationRefreshAttempted advances and persists the retry schedule
// before a Hub request begins. The name is retained as the SDK-store mutation
// boundary; it no longer consumes a one-shot operator approval.
func MarkRegistrationRefreshAttempted(dir string) error {
	return withRefreshMarkerNamespace(dir, markRegistrationRefreshAttempted)
}

func markRegistrationRefreshAttempted(namespace *pinnedfs.Directory) error {
	m, present, err := loadRegistrationRefreshMarker(namespace)
	if err != nil {
		return err
	}
	if !present {
		return nil
	}
	if m.AttemptCount == ^uint32(0) {
		return errors.New("registration refresh attempt count exhausted")
	}
	m.AttemptCount++
	now := time.Now()
	m.LastAttemptUnixMilli = now.UnixMilli()
	m.NextAttemptUnixMilli = now.Add(refreshRetryBackoff(m.AttemptCount)).UnixMilli()
	return writeRefreshMarker(namespace, m)
}

func refreshRetryBackoff(attempt uint32) time.Duration {
	base := refreshRetryInitial
	for i := uint32(1); i < attempt && base < refreshRetryMaximum; i++ {
		base *= 2
		if base > refreshRetryMaximum {
			base = refreshRetryMaximum
		}
	}
	half := base / 2
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return base
	}
	return half + time.Duration(binary.BigEndian.Uint64(raw[:])%uint64(base-half+1))
}

// ClearRegistrationRefreshMarker removes the registration-refresh marker,
// ending the current self-heal episode. It is called only after the complete
// NHP/FRP cycle reaches ProxyPhaseRunning, so steady-state restarts stay on the
// efficient persisted-assignment path without treating admission alone as
// proof that the public route is serving.
// It is deliberately NOT called when an assignment refresh succeeds: a Hub
// response proves only assignment, and a successful knock proves only
// admission. Only a genuinely serving FRP proxy clears the marker. See the
// RefreshMarker type doc for the full invariant. Absence is success — the
// marker not existing is exactly the desired post-condition. A non-ENOENT
// remove fault is returned for logging.
func ClearRegistrationRefreshMarker(dir string) error {
	return withRefreshMarkerNamespace(dir, clearRegistrationRefreshMarker)
}

func clearRegistrationRefreshMarker(namespace *pinnedfs.Directory) error {
	path := filepath.Join(namespace.Path(), RefreshMarkerFile)
	if err := namespace.Remove(RefreshMarkerFile); err != nil && !pinnedfs.IsNotExist(err) {
		return fmt.Errorf("remove registration refresh marker %s: %w", path, err)
	}
	if err := namespace.Sync(); err != nil {
		return fmt.Errorf("sync registration refresh marker removal %s: %w", path, err)
	}
	return namespace.ValidateCurrent()
}

// writeRefreshMarker atomically persists m under dir. Mode 0644 (non-secret
// breadcrumb) via the same atomicfile.Write (<name>.tmp + fsync + rename)
// the native state writes use, so a crash mid-write leaves either the prior
// marker or the new one — never a torn file the warm-restart read would
// reject.
func writeRefreshMarker(namespace *pinnedfs.Directory, m RefreshMarker) (retErr error) {
	data, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("encode registration refresh marker: %w", err)
	}
	path := filepath.Join(namespace.Path(), RefreshMarkerFile)
	if info, err := namespace.Lstat(RefreshMarkerFile); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("registration refresh marker %s must be a non-symlink regular file", path)
		}
		if info.Mode().Perm() != pubMode {
			return fmt.Errorf("registration refresh marker %s has mode %04o, want %04o", path, info.Mode().Perm(), pubMode)
		}
	} else if !pinnedfs.IsNotExist(err) {
		return fmt.Errorf("inspect registration refresh marker %s before write: %w", path, err)
	}

	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return fmt.Errorf("generate registration refresh marker temporary name: %w", err)
	}
	tmpName := "." + RefreshMarkerFile + ".tmp-" + hex.EncodeToString(suffix)
	tmp, err := namespace.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_EXCL|pinnedfs.SafeOpenFlags(), pubMode)
	if err != nil {
		return fmt.Errorf("create registration refresh marker temporary file: %w", err)
	}
	committed := false
	tmpOpen := true
	defer func() {
		if committed {
			if tmpOpen {
				retErr = errors.Join(retErr, closeRefreshMarkerFile(tmp))
			}
			return
		}
		var closeErr error
		if tmpOpen {
			closeErr = closeRefreshMarkerFile(tmp)
		}
		removeErr := removeRefreshMarkerTemp(namespace, tmpName)
		if pinnedfs.IsNotExist(removeErr) {
			removeErr = nil
		}
		syncErr := syncRefreshMarkerNamespace(namespace)
		retErr = errors.Join(retErr, closeErr, removeErr, syncErr)
	}()
	if err := tmp.Chmod(pubMode); err != nil {
		return fmt.Errorf("set registration refresh marker temporary permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("write registration refresh marker temporary file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync registration refresh marker temporary file: %w", err)
	}
	beforeRefreshMarkerTempValidation(namespace, tmpName)
	if _, err := pinnedfs.ValidateRegularFile(namespace, tmpName, tmp, "temporary registration refresh marker", pubMode); err != nil {
		return err
	}
	if err := namespace.ValidateCurrent(); err != nil {
		return fmt.Errorf("validate registration refresh marker namespace before commit: %w", err)
	}
	if err := namespace.Rename(tmpName, RefreshMarkerFile); err != nil {
		return fmt.Errorf("commit registration refresh marker rename: %w", err)
	}
	committed = true
	_, validationErr := pinnedfs.ValidateRegularFile(namespace, RefreshMarkerFile, tmp, "committed registration refresh marker", pubMode)
	closeErr := closeRefreshMarkerFile(tmp)
	tmpOpen = false
	syncErr := syncRefreshMarkerNamespace(namespace)
	continuityErr := namespace.ValidateCurrent()
	var wrappedSyncErr error
	if syncErr != nil {
		wrappedSyncErr = fmt.Errorf("registration refresh marker rename committed but namespace sync failed: %w", syncErr)
	}
	return errors.Join(validationErr, closeErr, wrappedSyncErr, continuityErr)
}
