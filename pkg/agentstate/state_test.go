package agentstate

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/layervai/qurl-connector/internal/pinnedfs"
)

// setSystemDefaultUsable pins the writability-driven ResolveDir branch for a
// test: true models a usable system default (root/service install, or a
// non-root container whose writable state volume is mounted there); false models
// a non-root developer whose /var/lib is root-owned.
func setSystemDefaultUsable(t *testing.T, usable bool) {
	t.Helper()
	prev := stateDirUsableAtSystemDefault
	stateDirUsableAtSystemDefault = func() bool { return usable }
	t.Cleanup(func() { stateDirUsableAtSystemDefault = prev })
}

// clearStateDirEnv removes the state-dir override so a branch under test is
// not perturbed by the developer's ambient environment.
func clearStateDirEnv(t *testing.T) {
	t.Helper()
	t.Setenv(EnvStateDirPrimary, "")
}

func TestResolveDirOverrideAndEnvPrecedence(t *testing.T) {
	// Pin the fallback to XDG so any accidental fall-through would be an obvious
	// mismatch against the env values under test — the overrides must win over
	// the writability-driven default regardless of which branch it would pick.
	setSystemDefaultUsable(t, false)
	explicit := filepath.Join(t.TempDir(), "explicit")
	primary := filepath.Join(t.TempDir(), "primary")
	// Explicit argument wins over everything, and whitespace is trimmed.
	t.Setenv(EnvStateDirPrimary, primary)
	if got := ResolveDir("  " + explicit + "  "); got != explicit {
		t.Fatalf("ResolveDir(explicit) = %q, want %q", got, explicit)
	}

	// QURL_CONNECTOR_STATE_DIR is the only environment override.
	if got := ResolveDir(""); got != primary {
		t.Fatalf("ResolveDir with env = %q, want the QURL_CONNECTOR_STATE_DIR value %q", got, primary)
	}
}

// TestResolveDirUsesSystemDefaultWhenUsable pins the hardened-container
// regression: the image runs as a non-root UID on a read-only rootfs with its
// only writable state path bind-mounted at the system default. When that path is
// usable, ResolveDir MUST return it (never an XDG path on the read-only rootfs),
// regardless of uid. It also covers root / service installs.
func TestResolveDirUsesSystemDefaultWhenUsable(t *testing.T) {
	clearStateDirEnv(t)
	setSystemDefaultUsable(t, true)
	// A writable XDG base is present but must be ignored: the system default is
	// usable, so it wins even for a non-root process.
	t.Setenv("XDG_STATE_HOME", filepath.Join(t.TempDir(), "xdg-state"))
	if got := ResolveDir(""); got != DefaultStateDir {
		t.Fatalf("ResolveDir with a usable system default = %q, want %q", got, DefaultStateDir)
	}
}

func TestResolveDirFallsBackToXDGWhenSystemDefaultUnusable(t *testing.T) {
	clearStateDirEnv(t)
	setSystemDefaultUsable(t, false)

	xdgBase := filepath.Join(t.TempDir(), "xdg-state")
	t.Setenv("XDG_STATE_HOME", xdgBase)
	wantXDG := filepath.Join(xdgBase, xdgStateSubdir)
	if got := ResolveDir(""); got != wantXDG {
		t.Fatalf("ResolveDir non-root with XDG_STATE_HOME = %q, want %q", got, wantXDG)
	}

	// A relative XDG_STATE_HOME is ignored (per the XDG base-dir spec) and
	// resolution falls to ~/.local/state.
	home := filepath.Join(t.TempDir(), "home")
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_STATE_HOME", "relative/not/absolute")
	wantHome := filepath.Join(home, ".local", "state", xdgStateSubdir)
	if got := ResolveDir(""); got != wantHome {
		t.Fatalf("ResolveDir non-root without XDG_STATE_HOME = %q, want %q", got, wantHome)
	}
}

func TestEnsureDirModeCreatesAndTightensTo0700(t *testing.T) {
	// A pinned-fs-safe base (symlinks resolved) so the EnsurePrivate assertion
	// below exercises the real validation path.
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	t.Run("creates a missing directory at 0700", func(t *testing.T) {
		dir := filepath.Join(base, "created", "state")
		if err := EnsureDirMode(dir); err != nil {
			t.Fatalf("EnsureDirMode(fresh) = %v", err)
		}
		if runtime.GOOS == "windows" {
			namespace, err := pinnedfs.OpenPrivate(dir, 0o700)
			if err != nil {
				t.Fatalf("fresh Windows state directory is not protected: %v", err)
			}
			if err := namespace.Close(); err != nil {
				t.Fatal(err)
			}
			return
		}
		if got := statMode(t, dir); got != 0o700 {
			t.Fatalf("fresh dir mode = %04o, want 0700", got)
		}
	})

	t.Run("tightens a pre-existing 0755 directory", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("the greenfield Windows ACL contract does not adopt an existing directory")
		}
		dir := filepath.Join(base, "loose")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		// A restrictive umask can drop the requested bits on Mkdir; assert the
		// starting condition so the tightening below is a real transition.
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := EnsureDirMode(dir); err != nil {
			t.Fatalf("EnsureDirMode(0755) = %v", err)
		}
		if got := statMode(t, dir); got != 0o700 {
			t.Fatalf("tightened dir mode = %04o, want 0700", got)
		}
		// The whole point: the pinned layer that rejected the 0755 dir now
		// accepts it, so a first run no longer dies on the mode check.
		ns, err := pinnedfs.EnsurePrivate(dir, dirMode)
		if err != nil {
			t.Fatalf("EnsurePrivate after tightening = %v, want success", err)
		}
		if err := ns.Close(); err != nil {
			t.Fatalf("close pinned namespace: %v", err)
		}
	})

	t.Run("rejects an empty path", func(t *testing.T) {
		if err := EnsureDirMode("   "); err == nil {
			t.Fatal("EnsureDirMode(blank) = nil, want an error")
		}
	})
}

func statMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}
