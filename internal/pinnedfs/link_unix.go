//go:build unix

package pinnedfs

import (
	"fmt"
	"os"
	"syscall"
)

// RequireSingleLinkInfo rejects an aliased file from one stable stat snapshot.
// A second hard link would permit mutation outside the pinned namespace.
func RequireSingleLinkInfo(info os.FileInfo, label string) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("inspect link count for %s: unsupported stat result %T", label, info.Sys())
	}
	if stat.Nlink != 1 {
		return fmt.Errorf("%s link count is %d, want 1", label, stat.Nlink)
	}
	return nil
}
