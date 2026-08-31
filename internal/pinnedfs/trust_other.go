//go:build !darwin && !linux && !windows

package pinnedfs

import "os"

func validateTrustedDirectory(_ os.FileInfo, _ string, _ bool) error {
	return ErrUnsupported
}

func validateTrustedReadOnlyInfo(_ os.FileInfo, _ string) error {
	return ErrUnsupported
}
