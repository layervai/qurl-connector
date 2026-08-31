package pinnedfs

import (
	"fmt"
	"os"
)

var beforeRegularFileFinalDescriptorValidation = func(*Directory, string, *os.File) {}
var beforeRegularFileFinalEntryValidation = func(*Directory, string, *os.File) {}

// ValidateRegularFile proves that file is an owner-owned, single-link regular
// file with the exact mode and that its descriptor still matches name in the
// retained namespace. The final descriptor and entry checks close substitution
// windows around callers' reads, locks, and atomic renames.
func ValidateRegularFile(namespace *Directory, name string, file *os.File, label string, mode os.FileMode) (os.FileInfo, error) {
	return validateRegularFile(namespace, name, file, label, func(current *os.File, info os.FileInfo, currentLabel string) error {
		return validatePrivateRegularFile(current, info, currentLabel, mode, true)
	})
}

// ValidateOwnerRegularFile proves the same descriptor-entry continuity as
// ValidateRegularFile while accepting any mode on an euid-owned Unix file. On
// Windows, modes do not express ACL safety, so there is no relaxed repair
// variant: this keeps the strict protected owner-only ACL requirement. A
// Windows file whose ACL drifted remains rejected and requires operator action
// outside the running Connector. This function is for safe cleanup or Unix
// mode repair of private state. Callers must restore and revalidate the
// required mode before they read or execute that state.
func ValidateOwnerRegularFile(namespace *Directory, name string, file *os.File, label string) (os.FileInfo, error) {
	return validateRegularFile(namespace, name, file, label, func(current *os.File, info os.FileInfo, currentLabel string) error {
		return validatePrivateRegularFile(current, info, currentLabel, info.Mode().Perm(), false)
	})
}

// ValidateTrustedReadOnlyFile proves the same descriptor-entry continuity as
// ValidateRegularFile while accepting a root- or euid-owned file with any
// read bits and no group/other write bits. It is for immutable customer config
// snapshots, never writable state.
func ValidateTrustedReadOnlyFile(namespace *Directory, name string, file *os.File, label string) (os.FileInfo, error) {
	return validateRegularFile(namespace, name, file, label, validateTrustedReadOnlyFile)
}

func validateRegularFile(
	namespace *Directory,
	name string,
	file *os.File,
	label string,
	validate func(*os.File, os.FileInfo, string) error,
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
	if err := validate(file, opened, label); err != nil {
		return nil, err
	}
	entry, err := namespace.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("inspect %s entry: %w", label, err)
	}
	if err := validateRegularEntry(entry, label+" entry", validate); err != nil {
		return nil, err
	}
	if !os.SameFile(opened, entry) {
		return nil, fmt.Errorf("%s descriptor no longer matches its namespace entry", label)
	}
	beforeRegularFileFinalDescriptorValidation(namespace, name, file)
	latest, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("final stat opened %s: %w", label, err)
	}
	if err := validate(file, latest, label); err != nil {
		return nil, err
	}
	beforeRegularFileFinalEntryValidation(namespace, name, file)
	latestEntry, err := namespace.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("final inspect %s entry: %w", label, err)
	}
	if err := validateRegularEntry(latestEntry, label+" final entry", validate); err != nil {
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

func validateRegularEntryShape(info os.FileInfo, label string) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("%s must be a non-symlink regular file", label)
	}
	return nil
}
