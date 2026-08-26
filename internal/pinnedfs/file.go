package pinnedfs

import (
	"fmt"
	"os"
)

// ValidateRegularFile proves that file is an owner-owned, single-link regular
// file with the exact mode and that its descriptor still matches name in the
// retained namespace. The final descriptor and entry checks close substitution
// windows around callers' reads, locks, and atomic renames.
func ValidateRegularFile(namespace *Directory, name string, file *os.File, label string, mode os.FileMode) (os.FileInfo, error) {
	return validateRegularFile(namespace, name, file, label, func(info os.FileInfo, currentLabel string) error {
		return validateRegularDescriptor(info, currentLabel, mode)
	})
}

// ValidateTrustedReadOnlyFile proves the same descriptor-entry continuity as
// ValidateRegularFile while accepting a root- or euid-owned file with any
// read bits and no group/other write bits. It is for immutable customer config
// snapshots, never writable state.
func ValidateTrustedReadOnlyFile(namespace *Directory, name string, file *os.File, label string) (os.FileInfo, error) {
	return validateRegularFile(namespace, name, file, label, validateTrustedReadOnlyDescriptor)
}

func validateRegularFile(
	namespace *Directory,
	name string,
	file *os.File,
	label string,
	validate func(os.FileInfo, string) error,
) (os.FileInfo, error) {
	if namespace == nil || file == nil {
		return nil, fmt.Errorf("%s is not open", label)
	}
	if err := namespace.ValidateCurrent(); err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat opened %s: %w", label, err)
	}
	if err := validate(opened, label); err != nil {
		return nil, err
	}
	entry, err := namespace.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("inspect %s entry: %w", label, err)
	}
	if err := validate(entry, label+" entry"); err != nil {
		return nil, err
	}
	if !os.SameFile(opened, entry) {
		return nil, fmt.Errorf("%s descriptor no longer matches its namespace entry", label)
	}
	latest, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("final stat opened %s: %w", label, err)
	}
	if err := validate(latest, label); err != nil {
		return nil, err
	}
	latestEntry, err := namespace.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("final inspect %s entry: %w", label, err)
	}
	if err := validate(latestEntry, label+" final entry"); err != nil {
		return nil, err
	}
	if !os.SameFile(latest, latestEntry) {
		return nil, fmt.Errorf("%s descriptor no longer matches its final namespace entry", label)
	}
	if err := namespace.ValidateCurrent(); err != nil {
		return nil, err
	}
	return latest, nil
}

func validateRegularDescriptor(info os.FileInfo, label string, mode os.FileMode) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("%s must be a non-symlink regular file", label)
	}
	if info.Mode().Perm() != mode.Perm() {
		return fmt.Errorf("%s mode is %04o, want %04o", label, info.Mode().Perm(), mode.Perm())
	}
	if err := RequireSingleLinkInfo(info, label); err != nil {
		return err
	}
	return RequireCurrentOwnerInfo(info, label)
}

func validateTrustedReadOnlyDescriptor(info os.FileInfo, label string) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("%s must be a non-symlink regular file", label)
	}
	if err := RequireSingleLinkInfo(info, label); err != nil {
		return err
	}
	return validateTrustedReadOnlyInfo(info, label)
}
