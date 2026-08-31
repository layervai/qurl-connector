//go:build unix

package pinnedfs

import (
	"fmt"
	"os"
)

// validateOwnerRegularDescriptor is retained as the descriptor-only Unix
// primitive used by the focused ownership tests and unsupported-Unix builds.
func validateOwnerRegularDescriptor(info os.FileInfo, label string) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("%s must be a non-symlink regular file", label)
	}
	if err := RequireSingleLinkInfo(info, label); err != nil {
		return err
	}
	return RequireCurrentOwnerInfo(info, label)
}
