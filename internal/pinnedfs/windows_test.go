//go:build windows

package pinnedfs

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestWindowsPrivateDirectoryRoundTripAndAtomicReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "qurl", "connector")
	namespace, err := EnsurePrivate(path, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	writeWindowsPinnedTestFile(t, namespace, ".state.tmp", "state.json", []byte("one"))
	writeWindowsPinnedTestFile(t, namespace, ".state.tmp", "state.json", []byte("two"))
	if err := namespace.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenPrivate(path, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	file, err := reopened.OpenFile("state.json", os.O_RDONLY|SafeOpenFlags(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := ValidateRegularFile(reopened, "state.json", file, "Windows state", 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(path, "state.json"))
	if err != nil || string(raw) != "two" {
		t.Fatalf("state = %q, %v", raw, err)
	}
}

func TestWindowsAtomicReplacementSucceedsWhilePinnedReaderIsOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "qurl", "connector")
	namespace, err := EnsurePrivate(path, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	defer namespace.Close()
	writeWindowsPinnedTestFile(t, namespace, ".state-old.tmp", "state.json", []byte("old"))

	reader, err := namespace.OpenFile("state.json", os.O_RDONLY|SafeOpenFlags(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if _, err := ValidateRegularFile(namespace, "state.json", reader, "open Windows state reader", 0o600); err != nil {
		t.Fatal(err)
	}

	replacement, err := namespace.OpenFile(".state-new.tmp", os.O_WRONLY|os.O_CREATE|os.O_EXCL|SafeOpenFlags(), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := replacement.Chmod(0o600); err != nil {
		_ = replacement.Close()
		t.Fatal(err)
	}
	if _, err := replacement.Write([]byte("new")); err != nil {
		_ = replacement.Close()
		t.Fatal(err)
	}
	if err := replacement.Sync(); err != nil {
		_ = replacement.Close()
		t.Fatal(err)
	}
	if err := replacement.Close(); err != nil {
		t.Fatal(err)
	}
	if err := namespace.Rename(".state-new.tmp", "state.json"); err != nil {
		t.Fatalf("rename replacement over an open Windows reader: %v", err)
	}
	if err := namespace.Sync(); err != nil {
		t.Fatal(err)
	}

	oldRaw, err := io.ReadAll(reader)
	if err != nil || string(oldRaw) != "old" {
		t.Fatalf("open reader after replacement = %q, %v, want old snapshot", oldRaw, err)
	}
	newRaw, err := os.ReadFile(filepath.Join(path, "state.json"))
	if err != nil || string(newRaw) != "new" {
		t.Fatalf("replacement state = %q, %v, want new snapshot", newRaw, err)
	}
}

func writeWindowsPinnedTestFile(t *testing.T, namespace *Directory, temporary, committed string, raw []byte) {
	t.Helper()
	file, err := namespace.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|SafeOpenFlags(), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	open := true
	defer func() {
		if open {
			_ = file.Close()
			_ = namespace.Remove(temporary)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateRegularFile(namespace, temporary, file, "temporary Windows state", 0o600); err != nil {
		t.Fatal(err)
	}
	if err := namespace.Rename(temporary, committed); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateRegularFile(namespace, committed, file, "committed Windows state", 0o600); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	open = false
	if err := namespace.Sync(); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsPrivateFileRejectsHardlink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "qurl", "connector")
	namespace, err := EnsurePrivate(path, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	defer namespace.Close()
	writeWindowsPinnedTestFile(t, namespace, ".state.tmp", "state.json", []byte("state"))
	if err := os.Link(filepath.Join(path, "state.json"), filepath.Join(path, "alias.json")); err != nil {
		t.Fatal(err)
	}
	file, err := namespace.OpenFile("state.json", os.O_RDONLY|SafeOpenFlags(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := ValidateRegularFile(namespace, "state.json", file, "hard-linked Windows state", 0o600); err == nil {
		t.Fatal("hard-linked Windows state was accepted")
	}
}

func TestWindowsPrivateFileRejectsForeignDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "qurl", "connector")
	namespace, err := EnsurePrivate(path, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	defer namespace.Close()
	writeWindowsPinnedTestFile(t, namespace, ".state.tmp", "state.json", []byte("state"))
	setWindowsTestWorldACL(t, filepath.Join(path, "state.json"), windows.GENERIC_READ)
	file, err := namespace.OpenFile("state.json", os.O_RDONLY|SafeOpenFlags(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := ValidateRegularFile(namespace, "state.json", file, "insecure Windows state", 0o600); err == nil {
		t.Fatal("Windows state with a foreign DACL was accepted")
	}
}

func TestWindowsCreateOpenDoesNotAdoptPrecreatedForeignDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "qurl", "connector")
	namespace, err := EnsurePrivate(path, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	defer namespace.Close()
	name := "precreated.json"
	if err := os.WriteFile(filepath.Join(path, name), []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	setWindowsTestWorldACL(t, filepath.Join(path, name), windows.GENERIC_READ)
	file, err := namespace.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if file != nil {
		_ = file.Close()
		t.Fatal("create-open returned a file with a foreign DACL")
	}
	if err == nil {
		t.Fatal("create-open accepted a precreated file with a foreign DACL")
	}
	if raw, readErr := os.ReadFile(filepath.Join(path, name)); readErr != nil || string(raw) != "foreign" {
		t.Fatalf("rejected precreated file = %q, %v; want unchanged content", raw, readErr)
	}
}

func TestWindowsCreateOpenRejectsAppendFlag(t *testing.T) {
	path := filepath.Join(t.TempDir(), "qurl", "connector")
	namespace, err := EnsurePrivate(path, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	defer namespace.Close()
	if file, err := namespace.OpenFile("append.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600); file != nil || err == nil {
		t.Fatalf("create with O_APPEND = (%v, %v), want explicit rejection", file, err)
	}
}

func TestWindowsCreateOpenTruncatesExistingSecureFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "qurl", "connector")
	namespace, err := EnsurePrivate(path, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	defer namespace.Close()
	writeWindowsPinnedTestFile(t, namespace, ".state.tmp", "state.json", []byte("long content"))
	file, err := namespace.OpenFile("state.json", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("new")); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(filepath.Join(path, "state.json")); err != nil || string(raw) != "new" {
		t.Fatalf("truncated state = %q, %v", raw, err)
	}
}

func TestWindowsPathHelpersRejectDeviceNamespacesAndBuildUNC(t *testing.T) {
	for _, path := range []string{`\\?\C:\qurl\state`, `\\.\C:\qurl\state`} {
		if err := validateAbsoluteDirectoryPath(path); err == nil {
			t.Fatalf("device namespace %q was accepted", path)
		}
	}
	got, err := windowsNTPath(`\\server\share\qurl\state`)
	if err != nil {
		t.Fatal(err)
	}
	if want := `\??\UNC\server\share\qurl\state`; got != want {
		t.Fatalf("UNC NT path = %q, want %q", got, want)
	}
}

func TestNormalizeWindowsOpenErrorPreservesErrorsIs(t *testing.T) {
	exists := &os.PathError{Op: "openat", Path: "state", Err: normalizeWindowsOpenError(windows.ERROR_ALREADY_EXISTS)}
	if !errors.Is(exists, os.ErrExist) {
		t.Fatalf("already-exists wrapper = %v, want errors.Is(os.ErrExist)", exists)
	}
	missing := &os.PathError{Op: "openat", Path: "state", Err: normalizeWindowsOpenError(windows.ERROR_FILE_NOT_FOUND)}
	if !errors.Is(missing, os.ErrNotExist) {
		t.Fatalf("not-found wrapper = %v, want errors.Is(os.ErrNotExist)", missing)
	}
}

func TestWindowsPrivateDirectoryRejectsForeignDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "qurl", "connector")
	namespace, err := EnsurePrivate(path, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if err := namespace.Close(); err != nil {
		t.Fatal(err)
	}
	setWindowsTestWorldACL(t, path, windows.GENERIC_READ)
	if reopened, err := OpenPrivate(path, 0o700); reopened != nil || err == nil {
		t.Fatalf("directory with a foreign DACL = (%v, %v), want rejection", reopened, err)
	}
}

func TestWindowsPrivateDirectoryRejectsAncestorDeleteControl(t *testing.T) {
	base := t.TempDir()
	ancestor := filepath.Join(base, "qurl")
	path := filepath.Join(ancestor, "connector")
	namespace, err := EnsurePrivate(path, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if err := namespace.Close(); err != nil {
		t.Fatal(err)
	}
	setWindowsTestWorldACL(t, ancestor, windowsFileDeleteChild)
	if reopened, err := OpenPrivate(path, 0o700); reopened != nil || err == nil {
		t.Fatalf("directory below a replaceable ancestor = (%v, %v), want rejection", reopened, err)
	}
}

func TestWindowsEnsurePrivateRetriesOnlyProtectedExistingEdges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "qurl", "connector")
	original := syncPinnedParent
	var calls []string
	syncPinnedParent = func(_ *os.Root, edgePath string) error {
		calls = append(calls, edgePath)
		return nil
	}
	t.Cleanup(func() { syncPinnedParent = original })
	first, err := EnsurePrivate(path, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 {
		t.Fatalf("syncs for two created components = %v, want 2", calls)
	}
	calls = nil
	second, err := EnsurePrivate(path, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || calls[0] != filepath.Dir(path) || calls[1] != path {
		t.Fatalf("retry syncs for protected existing edges = %v, want [%s %s]", calls, filepath.Dir(path), path)
	}
}

func TestWindowsEnsurePrivateFailsWhenProtectedEdgeRetrySyncFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "qurl", "connector")
	first, err := EnsurePrivate(path, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	wantErr := errors.New("injected existing-edge sync failure")
	original := syncPinnedParent
	syncPinnedParent = func(_ *os.Root, edgePath string) error {
		if edgePath == path {
			return wantErr
		}
		return nil
	}
	t.Cleanup(func() { syncPinnedParent = original })
	if namespace, err := EnsurePrivate(path, 0o700); namespace != nil || !errors.Is(err, wantErr) {
		if namespace != nil {
			_ = namespace.Close()
		}
		t.Fatalf("EnsurePrivate retry = (%v, %v), want fail-closed sync error", namespace, err)
	}
}

func TestWindowsCreatedACLClassifierRequiresExactCreationSubjects(t *testing.T) {
	path := filepath.Join(t.TempDir(), "qurl", "connector")
	namespace, err := EnsurePrivate(path, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if err := namespace.Close(); err != nil {
		t.Fatal(err)
	}
	if !windowsTestMatchesCreatedACL(t, path) {
		t.Fatal("fresh protected directory did not match its creation ACL")
	}

	for _, tc := range []struct {
		name          string
		includeAdmin  bool
		includeSystem bool
	}{
		{name: "missing Administrators", includeSystem: true},
		{name: "missing SYSTEM", includeAdmin: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setWindowsTestPrivateACL(t, path, tc.includeAdmin, tc.includeSystem)
			if windowsTestMatchesCreatedACL(t, path) {
				t.Fatal("non-exact protected ACL matched the creation policy")
			}
		})
	}
}

func windowsTestMatchesCreatedACL(t *testing.T, path string) bool {
	t.Helper()
	handle, err := openWindowsDirectoryAbsolute(path, windows.FILE_GENERIC_READ|windows.READ_CONTROL|windows.SYNCHRONIZE)
	if err != nil {
		t.Fatal(err)
	}
	match, matchErr := matchesCreatedWindowsACL(handle, path)
	if err := errors.Join(matchErr, windows.CloseHandle(handle)); err != nil {
		t.Fatal(err)
	}
	return match
}

func setWindowsTestPrivateACL(t *testing.T, path string, includeAdmin, includeSystem bool) {
	t.Helper()
	current, _, err := currentWindowsSecurity()
	if err != nil {
		t.Fatal(err)
	}
	entries := []windows.EXPLICIT_ACCESS{windowsTestAccess(current, windows.GENERIC_ALL)}
	if includeAdmin {
		admin, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, windowsTestAccess(admin, windows.GENERIC_ALL))
	}
	if includeSystem {
		system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, windowsTestAccess(system, windows.GENERIC_ALL))
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsExclusiveFileLockSerializesAndCancels(t *testing.T) {
	path := filepath.Join(t.TempDir(), "qurl", "connector")
	first, err := EnsurePrivate(path, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := OpenPrivate(path, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	held, err := AcquireExclusiveFileLock(context.Background(), first, "state.lock", "Windows state lock", 0o600)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if lock, err := AcquireExistingExclusiveFileLock(ctx, second, "state.lock", "Windows state lock", 0o600); lock != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("contended lock = (%v, %v), want deadline", lock, err)
	}
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	acquired, err := AcquireExistingExclusiveFileLock(context.Background(), second, "state.lock", "Windows state lock", 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := acquired.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsSharedFileLocksCoexistAndExcludeWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "qurl", "connector")
	first, err := EnsurePrivate(path, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	seed, err := AcquireExclusiveFileLock(context.Background(), first, "state.lock", "Windows state lock", 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := seed.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := OpenPrivate(path, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	left, err := AcquireSharedFileLock(context.Background(), first, "state.lock", "Windows state lock", 0o600)
	if err != nil {
		t.Fatal(err)
	}
	right, err := AcquireSharedFileLock(context.Background(), second, "state.lock", "Windows state lock", 0o600)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if writer, err := AcquireExistingExclusiveFileLock(ctx, second, "state.lock", "Windows state lock", 0o600); writer != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("writer behind shared locks = (%v, %v), want deadline", writer, err)
	}
	if err := right.Close(); err != nil {
		t.Fatal(err)
	}
	if err := left.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsPrivateDirectoryRejectsReparseComponent(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "state")
	if err := os.Symlink(target, link); err != nil {
		if !errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) {
			t.Fatal(err)
		}
		if output, junctionErr := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); junctionErr != nil {
			t.Fatalf("create Windows junction: %v: %s", junctionErr, output)
		}
	}
	if namespace, err := EnsurePrivate(filepath.Join(link, "nested"), 0o700); namespace != nil || err == nil {
		t.Fatalf("reparse directory = (%v, %v), want rejection", namespace, err)
	}
}

func setWindowsTestWorldACL(t *testing.T, path string, worldMask windows.ACCESS_MASK) {
	t.Helper()
	current, _, err := currentWindowsSecurity()
	if err != nil {
		t.Fatal(err)
	}
	admin, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	world, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	entries := []windows.EXPLICIT_ACCESS{
		windowsTestAccess(current, windows.GENERIC_ALL),
		windowsTestAccess(admin, windows.GENERIC_ALL),
		windowsTestAccess(system, windows.GENERIC_ALL),
		windowsTestAccess(world, worldMask),
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
}

func windowsTestAccess(sid *windows.SID, mask windows.ACCESS_MASK) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: mask,
		AccessMode:        windows.GRANT_ACCESS,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}
