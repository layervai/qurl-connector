//go:build windows

package pinnedfs

import (
	"context"
	"errors"
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

func TestWindowsEnsurePrivateDoesNotSyncUnchangedAncestors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "qurl", "connector")
	original := syncPinnedParent
	var calls int
	syncPinnedParent = func(*os.Root, string) error {
		calls++
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
	if calls != 2 {
		t.Fatalf("syncs for two created components = %d, want 2", calls)
	}
	calls = 0
	second, err := EnsurePrivate(path, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatalf("syncs for unchanged ancestors = %d, want 0", calls)
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
