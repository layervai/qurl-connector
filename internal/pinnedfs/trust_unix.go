//go:build darwin || linux

package pinnedfs

import (
	"fmt"
	"os"
	"syscall"
)

// validateTrustedDirectory rejects path components an unrelated user can
// replace. Private state traversal may admit root-owned sticky ancestors
// (notably /tmp) because another user cannot replace an entry they do not own.
// Immutable configuration traversal is stricter and admits no group/other
// writable component at all.
func validateTrustedDirectory(info os.FileInfo, label string, allowSticky bool) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("inspect trust attributes for %s: unsupported stat result %T", label, info.Sys())
	}
	uid := int(stat.Uid)
	if uid != 0 && uid != os.Geteuid() {
		return fmt.Errorf("directory component %s owner uid is %d, want root or effective uid %d", label, uid, os.Geteuid())
	}
	if info.Mode().Perm()&0o022 == 0 {
		return nil
	}
	if allowSticky && uid == 0 && info.Mode()&os.ModeSticky != 0 {
		return nil
	}
	return fmt.Errorf("directory component %s has unsafe mode %04o", label, info.Mode().Perm())
}

// validateTrustedReadOnlyInfo accepts root/euid ownership with no group/other
// write bits. Unlike the directory traversal rule it does not admit sticky
// writable entries; a final read-only namespace or file must not be name-
// squattable by another user.
func validateTrustedReadOnlyInfo(info os.FileInfo, label string) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("inspect read-only trust attributes for %s: unsupported stat result %T", label, info.Sys())
	}
	uid := int(stat.Uid)
	if uid != 0 && uid != os.Geteuid() {
		return fmt.Errorf("%s owner uid is %d, want root or effective uid %d", label, uid, os.Geteuid())
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s has unsafe writable mode %04o", label, info.Mode().Perm())
	}
	return nil
}
