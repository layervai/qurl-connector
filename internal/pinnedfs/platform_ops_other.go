//go:build !darwin && !linux && !windows

package pinnedfs

import (
	"os"
)

func validateAbsoluteDirectoryPath(string) error { return ErrUnsupported }
func directoryWalkAnchor(string) string          { return "" }
func supportsConfinedRecovery() bool             { return false }
func syncExistingDirectoryEdges() bool           { return false }
func createPinnedDirectory(*os.Root, string, string, os.FileMode) error {
	return ErrUnsupported
}
func syncPinnedDirectory(*os.Root, string) error { return ErrUnsupported }
func validateTrustedDirectoryRoot(*os.Root, os.FileInfo, string, bool) error {
	return ErrUnsupported
}
func validateFinalDirectory(*os.Root, os.FileInfo, string, *os.FileMode, bool, bool) error {
	return ErrUnsupported
}
func validateOwnedDirectory(*os.Root, os.FileInfo, string) error { return ErrUnsupported }
func openPinnedFile(*os.Root, string, int, os.FileMode) (*os.File, error) {
	return nil, ErrUnsupported
}
