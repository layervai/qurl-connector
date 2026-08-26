// Package atomicfile provides a crash-safe file write primitive shared
// by the agent-state and bootstrap layers. Extracted from the
// duplicated implementations previously living in pkg/agentstate and
// state-marker writers so the durability shape has one source of truth.
//
// Internal by design — the only callers are layers that manage host-
// volume state for the qURL reverse-tunnel client (X25519 keypair,
// agent_id, tunnel-identity cache). Customers/consumers should reach
// for `golang.org/x/sys/unix` or `renameio` instead.
package atomicfile

import (
	"os"
	"path/filepath"
)

// Write writes data to path atomically: write to a temp file in the
// same directory, fsync the contents, then rename onto the target.
// Crash-safe in the sense that a partial write never leaves a
// half-baked file at `path` — the rename is the commit point.
//
// Durability shape (intentional):
//   - The temp file's contents are fsynced before the rename, so a
//     power loss between the write() and the rename() cannot surface
//     partial bytes at `path`.
//   - The PARENT directory is NOT fsynced after the rename. Linux
//     ext4 (the customer Docker install's expected fs) journals the
//     rename metadata so a post-rename crash is durable in practice.
//     fsync(parent) would buy us strict POSIX guarantees on weirder
//     filesystems but the host-volume use cases here (agent keypair,
//     tunnel-identity cache) are best-effort enough not to justify
//     the cost. Worst case on a non-journaling fs: the rename is
//     lost and the caller pays one extra recompute on next start.
//   - The temp file is removed on every failure path so a retried
//     Write doesn't trip over leftover `.tmp-*` siblings.
//
// If you change the durability shape, update this docstring AND any
// downstream contract docs that reference it (the bootstrap and
// agentstate godocs both point here).
func Write(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// On any failure path below, remove the temp file so a subsequent
	// retry doesn't trip over leftover .tmp-* entries. errcheck on
	// Remove is unsafe here — the file may already be moved.
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
