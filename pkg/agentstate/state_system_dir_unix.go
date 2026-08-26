//go:build darwin || linux

package agentstate

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// systemStateDirCreatable reports whether this process can create (or already
// write to) the system-default state directory. It is the production value
// behind stateDirUsableAtSystemDefault.
func systemStateDirCreatable() bool {
	return dirCreatableOrWritable(DefaultStateDir)
}

// dirCreatableOrWritable reports whether target exists and is writable, or does
// not exist but its nearest existing ancestor is writable (so target could be
// created). It walks up from target to the first extant component and checks
// write access there with access(2).
//
// This is exactly what distinguishes a non-root process whose writable state
// volume is mounted at the system default (the hardened container: UID 65532,
// read-only rootfs, /var/lib/layerv/agent bind-mounted writable) from a non-root
// developer on a normal filesystem where /var/lib is root-owned and read-only to
// them. access(2) also reports EROFS for an existing path on a read-only mount,
// so a read-only rootfs component correctly resolves to "not usable".
func dirCreatableOrWritable(target string) bool {
	for {
		err := unix.Access(target, unix.W_OK)
		if err == nil {
			return true
		}
		if !errors.Is(err, os.ErrNotExist) {
			// Exists but not writable (EACCES), on a read-only filesystem
			// (EROFS), or another hard error: not usable without elevation.
			return false
		}
		parent := filepath.Dir(target)
		if parent == target {
			return false
		}
		target = parent
	}
}
