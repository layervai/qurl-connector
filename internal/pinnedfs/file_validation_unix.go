//go:build darwin || linux

package pinnedfs

import (
	"fmt"
	"os"
)

func validatePrivateRegularFile(_ *os.File, info os.FileInfo, label string, mode os.FileMode, exactMode bool) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("%s must be a non-symlink regular file", label)
	}
	if exactMode && info.Mode().Perm() != mode.Perm() {
		return fmt.Errorf("%s mode is %04o, want %04o", label, info.Mode().Perm(), mode.Perm())
	}
	if err := RequireSingleLinkInfo(info, label); err != nil {
		return err
	}
	return RequireCurrentOwnerInfo(info, label)
}

func validateTrustedReadOnlyFile(_ *os.File, info os.FileInfo, label string) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("%s must be a non-symlink regular file", label)
	}
	if err := RequireSingleLinkInfo(info, label); err != nil {
		return err
	}
	return validateTrustedReadOnlyInfo(info, label)
}
