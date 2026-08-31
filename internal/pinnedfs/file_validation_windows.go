//go:build windows

package pinnedfs

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func validatePrivateRegularFile(file *os.File, _ os.FileInfo, label string, _ os.FileMode, _ bool) error {
	identity, info, err := windowsHandleIdentity(windows.Handle(file.Fd()))
	_ = identity
	if err != nil {
		return fmt.Errorf("stat %s: %w", label, err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%s must be a non-reparse regular file", label)
	}
	if info.NumberOfLinks != 1 {
		return fmt.Errorf("%s link count is %d, want 1", label, info.NumberOfLinks)
	}
	return validateSecureWindowsACL(windows.Handle(file.Fd()), label)
}

func validateTrustedReadOnlyFile(file *os.File, _ os.FileInfo, label string) error {
	_, info, err := windowsHandleIdentity(windows.Handle(file.Fd()))
	if err != nil {
		return fmt.Errorf("stat %s: %w", label, err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%s must be a non-reparse regular file", label)
	}
	if info.NumberOfLinks != 1 {
		return fmt.Errorf("%s link count is %d, want 1", label, info.NumberOfLinks)
	}
	return validateTrustedWindowsACL(windows.Handle(file.Fd()), label, false)
}
