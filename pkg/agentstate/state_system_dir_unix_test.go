//go:build darwin || linux

package agentstate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDirCreatableOrWritable(t *testing.T) {
	t.Run("existing writable directory is usable", func(t *testing.T) {
		// Models the hardened container's state volume: the mount point exists
		// and is writable by the runtime UID.
		if !dirCreatableOrWritable(t.TempDir()) {
			t.Fatal("dirCreatableOrWritable(writable dir) = false, want true")
		}
	})

	t.Run("missing path under a writable ancestor is creatable", func(t *testing.T) {
		// Models root/service install where /var/lib/layerv/agent does not yet
		// exist but its parent is writable.
		target := filepath.Join(t.TempDir(), "layerv", "agent")
		if !dirCreatableOrWritable(target) {
			t.Fatalf("dirCreatableOrWritable(%q) = false, want true (nearest ancestor writable)", target)
		}
	})

	t.Run("missing path under a non-writable ancestor is not usable", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("running as root bypasses DAC write checks; the non-writable branch is unobservable")
		}
		// Models the non-root developer whose system-default parent is
		// read/execute-only to them: nothing can be created underneath it.
		base := t.TempDir()
		locked := filepath.Join(base, "locked")
		if err := os.Mkdir(locked, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(locked, 0o700) }) // let t.TempDir cleanup remove it
		target := filepath.Join(locked, "layerv", "agent")
		if dirCreatableOrWritable(target) {
			t.Fatalf("dirCreatableOrWritable(%q) = true, want false (ancestor not writable)", target)
		}
	})
}
