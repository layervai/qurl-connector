//go:build darwin || linux

package pinnedfs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func validateAbsoluteDirectoryPath(path string) error {
	if filepath.VolumeName(path) != "" || !filepath.IsAbs(path) {
		return fmt.Errorf("directory path %s is not an absolute Unix path", path)
	}
	return nil
}

func directoryWalkAnchor(string) string { return string(filepath.Separator) }

func supportsConfinedRecovery() bool { return true }

func shouldRetryDirectoryEdgeSync(*os.Root, string) (bool, error) { return true, nil }

func createPinnedDirectory(parent *os.Root, name, path string, mode os.FileMode) error {
	if err := parent.Mkdir(name, mode.Perm()); err != nil {
		return err
	}
	// mkdir honors the process umask. Force the requested mode through the
	// retained parent before opening the new edge.
	if err := chmodPinnedChild(parent, name, mode.Perm()); err != nil {
		removeErr := removePinnedChild(parent, name)
		syncErr := syncPinnedParent(parent, path)
		return errors.Join(
			fmt.Errorf("set directory component permissions: %w", err),
			wrapDirectoryCleanupError(path, "remove after permission failure", removeErr),
			wrapDirectoryCleanupError(path, "sync parent after permission-failure cleanup", syncErr),
		)
	}
	return nil
}

func syncPinnedDirectory(root *os.Root, label string) error {
	dir, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open parent for %s durability sync: %w", label, err)
	}
	return errors.Join(dir.Sync(), dir.Close())
}

func validateTrustedDirectoryRoot(_ *os.Root, info os.FileInfo, label string, allowSticky bool) error {
	return validateTrustedDirectory(info, label, allowSticky)
}

func validateFinalDirectory(_ *os.Root, info os.FileInfo, label string, exactMode *os.FileMode, requireOwner, requireTrust bool) error {
	if exactMode != nil && info.Mode().Perm() != exactMode.Perm() {
		return fmt.Errorf("directory %s has mode %04o, want %04o", label, info.Mode().Perm(), exactMode.Perm())
	}
	if requireOwner {
		if err := validateCurrentOwner(info, label); err != nil {
			return err
		}
	}
	if requireTrust {
		return validateTrustedReadOnlyInfo(info, label)
	}
	return nil
}

func validateOwnedDirectory(_ *os.Root, info os.FileInfo, label string) error {
	if err := validateCurrentOwner(info, label); err != nil {
		if trustedErr := validateTrustedReadOnlyInfo(info, label); trustedErr == nil {
			return fmt.Errorf("%w: %w", ErrNamespaceNotOwned, err)
		}
		return err
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("transaction namespace %s has mode %04o, want no group/other write", label, info.Mode().Perm())
	}
	return nil
}

func openPinnedFile(root *os.Root, name string, flag int, perm os.FileMode) (*os.File, error) {
	return root.OpenFile(name, flag, perm)
}
