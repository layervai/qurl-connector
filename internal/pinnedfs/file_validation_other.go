//go:build !darwin && !linux && !windows

package pinnedfs

import "os"

func validatePrivateRegularFile(*os.File, os.FileInfo, string, os.FileMode, bool) error {
	return ErrUnsupported
}
func validateTrustedReadOnlyFile(*os.File, os.FileInfo, string) error { return ErrUnsupported }
