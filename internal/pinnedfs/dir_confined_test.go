//go:build darwin || linux

package pinnedfs

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// confinedTree builds root/confined/container/target where `confined` is
// traversable but not openable (mode 0111). That is the shape macOS App Sandbox
// imposes: a process may resolve paths *through* an ancestor it is not allowed
// to open as a directory handle, and the container below it opens normally.
// requireNonRoot guards a fixture that depends on discretionary access control.
// root bypasses the mode bits these tests use to simulate confinement, so the
// tree would not actually be confined and the test would assert the wrong thing.
//
// Skipping locally is right -- a real sandbox cannot be built in a unit test, so
// a root developer shell has no way to run these. Skipping in CI is not: it
// would take the entire confined code path out of coverage and still report
// green, which is the exact failure that let this package go untested for
// weeks. Under CI, be loud instead.
func requireNonRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		return
	}
	const reason = "confinement fixtures rely on DAC; root bypasses the mode bits they set"
	if os.Getenv("CI") != "" {
		t.Fatalf("%s -- running CI as root silently drops every confinement test", reason)
	}
	t.Skip(reason)
}

func confinedTree(t *testing.T) (confined, container, target string) {
	t.Helper()
	requireNonRoot(t)
	root := realTempDir(t)
	confined = filepath.Join(root, "confined")
	container = filepath.Join(confined, "container")
	target = filepath.Join(container, "target")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(confined, 0o111); err != nil {
		t.Fatal(err)
	}
	// Restore before TempDir cleanup: RemoveAll cannot list a 0111 directory.
	t.Cleanup(func() { _ = os.Chmod(confined, 0o700) })
	return confined, container, target
}

func TestOpenTrustedPinsThroughAnUnopenableAncestor(t *testing.T) {
	confined, container, target := confinedTree(t)

	dir, err := OpenTrusted(target)
	if err != nil {
		t.Fatalf("OpenTrusted through confined ancestor: %v", err)
	}
	defer dir.Close()

	if dir.Path() != target {
		t.Fatalf("pinned path = %s, want %s", dir.Path(), target)
	}
	// Validation must resume at the shallowest reachable prefix, so the
	// container itself is still validated -- not just the leaf.
	if dir.anchor != container {
		t.Fatalf("anchor = %s, want %s (confined ancestor was %s)", dir.anchor, container, confined)
	}
}

func TestEnsureCreatesBeneathAnUnopenableAncestor(t *testing.T) {
	_, container, target := confinedTree(t)
	nested := filepath.Join(target, "a", "b")

	dir, err := EnsurePrivate(nested, 0o700)
	if err != nil {
		t.Fatalf("EnsurePrivate through confined ancestor: %v", err)
	}
	defer dir.Close()
	if dir.anchor != container {
		t.Fatalf("anchor = %s, want %s", dir.anchor, container)
	}
	if _, err := os.Stat(nested); err != nil {
		t.Fatalf("nested directory not created: %v", err)
	}
}

// The fallback narrows where validation starts. It must not narrow what is
// validated below that point.
func TestConfinedFallbackStillRejectsSymlinkBelowAnchor(t *testing.T) {
	_, container, target := confinedTree(t)
	link := filepath.Join(container, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	dir, err := OpenTrusted(filepath.Join(link, "child"))
	if err == nil {
		dir.Close()
		t.Fatal("OpenTrusted accepted a symlink component below the anchor")
	}
	if got := err.Error(); !strings.Contains(got, "must not be a symlink") {
		t.Fatalf("error = %q, want a symlink rejection", got)
	}
}

func TestConfinedFallbackStillRejectsUnsafeModeBelowAnchor(t *testing.T) {
	_, _, target := confinedTree(t)
	// Intermediate, not final: the per-edge trust check is a different code
	// path from the final-attribute check, and the fallback must keep both.
	loose := filepath.Join(target, "loose")
	leaf := filepath.Join(loose, "leaf")
	if err := os.MkdirAll(leaf, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o777); err != nil {
		t.Fatal(err)
	}

	dir, err := OpenTrusted(leaf)
	if err == nil {
		dir.Close()
		t.Fatal("OpenTrusted accepted a world-writable component below the anchor")
	}
	if got := err.Error(); !strings.Contains(got, "unsafe mode") {
		t.Fatalf("error = %q, want an unsafe-mode rejection", got)
	}
}

// A symlink *between* the denied ancestor and the anchor is the dangerous one:
// those components can never be reached with a pinned handle, and os.OpenRoot
// follows whatever path it is handed. Without an explicit check a link planted
// in that band is traversed silently rather than rejected.
func TestSymlinkInsideTheConfinedBandIsRejected(t *testing.T) {
	requireNonRoot(t)
	root := realTempDir(t)
	real := filepath.Join(root, "real")
	if err := os.MkdirAll(filepath.Join(real, "target"), 0o700); err != nil {
		t.Fatal(err)
	}
	confined := filepath.Join(root, "confined")
	if err := os.Mkdir(confined, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(confined, "link")); err != nil {
		t.Fatal(err)
	}
	// Traversable but not openable, so the walk from / stops here and the band
	// below it is exactly the part that cannot be validated with handles.
	if err := os.Chmod(confined, 0o111); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(confined, 0o700) })

	dir, err := OpenTrusted(filepath.Join(confined, "link", "target"))
	if err == nil {
		dir.Close()
		t.Fatal("OpenTrusted followed a symlink inside the confined band")
	}
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("error = %v, want the original permission error", err)
	}
}

// The App Sandbox band is several components deep, not one. Anchoring must skip
// the whole contiguous run, not stop at the first denied-or-openable boundary.
func TestWalkSkipsAContiguousMultiComponentBand(t *testing.T) {
	requireNonRoot(t)
	root := realTempDir(t)
	outer := filepath.Join(root, "outer")
	inner := filepath.Join(outer, "inner")
	container := filepath.Join(inner, "container")
	target := filepath.Join(container, "target")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	// Two stacked traverse-only ancestors: the walk must not anchor at either.
	if err := os.Chmod(inner, 0o111); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(outer, 0o111); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(outer, 0o700)
		_ = os.Chmod(inner, 0o700)
	})

	dir, err := OpenTrusted(target)
	if err != nil {
		t.Fatalf("OpenTrusted through a two-component band: %v", err)
	}
	defer dir.Close()
	if dir.anchor != container {
		t.Fatalf("anchor = %s, want %s (band was %s then %s)", dir.anchor, container, outer, inner)
	}
}

// A band component can be BOTH unopenable and group/other-writable: mode 0333
// is traversable, not readable, and writable by anyone. Such a component is
// skipped by the reachability probe entirely, so if the band is not trust
// checked an attacker-writable directory sits unvalidated in the resolved path.
func TestGroupWritableComponentInTheConfinedBandIsRejected(t *testing.T) {
	requireNonRoot(t)
	root := realTempDir(t)
	confined := filepath.Join(root, "confined")
	evil := filepath.Join(confined, "evil")
	target := filepath.Join(evil, "target")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(evil, 0o333); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(confined, 0o111); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(confined, 0o700)
		_ = os.Chmod(evil, 0o700)
	})

	dir, err := OpenTrusted(target)
	if err == nil {
		dir.Close()
		t.Fatal("OpenTrusted resumed below a world-writable band component")
	}
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("error = %v, want the original permission error", err)
	}
}

// The fallback keys on permission denials only. A symlink ancestor must not let
// an attacker skip validation by getting the walk to resume below the link.
func TestSymlinkAncestorIsNotRecoveredByFallback(t *testing.T) {
	root := realTempDir(t)
	real := filepath.Join(root, "real", "target")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(filepath.Join(root, "real"), link); err != nil {
		t.Fatal(err)
	}

	dir, err := OpenTrusted(filepath.Join(link, "target"))
	if err == nil {
		dir.Close()
		t.Fatal("OpenTrusted accepted a symlink ancestor")
	}
	if got := err.Error(); !strings.Contains(got, "must not be a symlink") {
		t.Fatalf("error = %q, want a symlink rejection", got)
	}
}

// Open and Ensure take a distinct branch through the fallback: they skip the
// trust checks in both the band scan and the walk. pkg/agentstate and the
// identity cache reach the confined path through these, so cover them directly
// rather than by proximity to the trusted tests.
func TestUntrustedEntryPointsRecoverThroughAConfinedAncestor(t *testing.T) {
	_, container, target := confinedTree(t)

	pinned, err := Open(target)
	if err != nil {
		t.Fatalf("Open through confined ancestor: %v", err)
	}
	defer pinned.Close()
	if pinned.anchor != container {
		t.Fatalf("Open anchor = %s, want %s", pinned.anchor, container)
	}

	created := filepath.Join(target, "made")
	dir, err := Ensure(created, 0o755)
	if err != nil {
		t.Fatalf("Ensure through confined ancestor: %v", err)
	}
	defer dir.Close()
	if dir.anchor != container {
		t.Fatalf("Ensure anchor = %s, want %s", dir.anchor, container)
	}
	if _, err := os.Stat(created); err != nil {
		t.Fatalf("Ensure did not create the directory: %v", err)
	}
}

// Recovery shortens the retained edge chain, and every mutation revalidates
// that chain first. Assert a real write goes through a recovered Directory --
// pinning it is worth little if operations on it then fail or skip validation.
func TestMutationsWorkThroughARecoveredDirectory(t *testing.T) {
	_, container, target := confinedTree(t)

	dir, err := OpenTrusted(target)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	if dir.anchor != container {
		t.Fatalf("anchor = %s, want %s", dir.anchor, container)
	}

	f, err := dir.OpenFile("state.lock", os.O_CREATE|os.O_RDWR|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatalf("OpenFile through a recovered directory: %v", err)
	}
	if _, err := f.WriteString("pinned"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := dir.Rename("state.lock", "state.final"); err != nil {
		t.Fatalf("Rename through a recovered directory: %v", err)
	}
	if err := dir.Sync(); err != nil {
		t.Fatalf("Sync through a recovered directory: %v", err)
	}
	if err := dir.ValidateCurrent(); err != nil {
		t.Fatalf("ValidateCurrent on a recovered directory: %v", err)
	}
	if err := dir.Remove("state.final"); err != nil {
		t.Fatalf("Remove through a recovered directory: %v", err)
	}
}

// A reachable tree must keep validating every component from the filesystem
// root. The fallback is only for ancestors this process genuinely cannot open.
func TestReachableTreeStillWalksFromFilesystemRoot(t *testing.T) {
	root := realTempDir(t)
	target := filepath.Join(root, "plain")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}

	dir, err := OpenTrusted(target)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	if dir.anchor != string(filepath.Separator) {
		t.Fatalf("anchor = %s, want the filesystem root", dir.anchor)
	}
}

// If nothing below the denied ancestor can be opened either, the caller must
// see the original permission error rather than a confusing fallback error.
func TestUnreachableTargetReturnsThePermissionError(t *testing.T) {
	requireNonRoot(t)
	root := realTempDir(t)
	confined := filepath.Join(root, "confined")
	target := filepath.Join(confined, "target")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	// 0000: neither openable nor traversable, so the target is unreachable too.
	if err := os.Chmod(confined, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(confined, 0o700) })

	_, err := OpenTrusted(target)
	if err == nil {
		t.Fatal("OpenTrusted succeeded through a fully denied ancestor")
	}
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("error = %v, want a permission error", err)
	}
}
