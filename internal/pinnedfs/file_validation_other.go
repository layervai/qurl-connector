//go:build !darwin && !linux && !windows

package pinnedfs

import "os"

func validatePrivateRegularFile(*os.File, os.FileInfo, string, os.FileMode, bool) error {
	return ErrUnsupported
}
func validateTrustedReadOnlyFile(*os.File, os.FileInfo, string) error { return ErrUnsupported }

func validateRegularEntry(info os.FileInfo, label string, validate func(*os.File, os.FileInfo, string) error) error {
	if err := validateRegularEntryShape(info, label); err != nil {
		return err
	}
	return validate(nil, info, label)
}
