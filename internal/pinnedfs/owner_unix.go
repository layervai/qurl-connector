//go:build unix

package pinnedfs

import (
	"fmt"
	"os"
	"syscall"
)

func validateCurrentOwner(info os.FileInfo, label string) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("inspect owner for %s: unsupported stat result %T", label, info.Sys())
	}
	if int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("%s owner uid is %d, want effective uid %d", label, stat.Uid, os.Geteuid())
	}
	return nil
}

// RequireCurrentOwnerInfo verifies ownership from one stable stat snapshot.
func RequireCurrentOwnerInfo(info os.FileInfo, label string) error {
	return validateCurrentOwner(info, label)
}
