//go:build windows

package pinnedfs

import (
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/windows"
)

func validatePrivateRegularFile(file *os.File, _ os.FileInfo, label string, _ os.FileMode, _ bool) error {
	defer func() { runtime.KeepAlive(file) }()
	handle := windows.Handle(file.Fd())
	_, info, err := windowsHandleIdentity(handle)
	if err != nil {
		return fmt.Errorf("stat %s: %w", label, err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%s must be a non-reparse regular file", label)
	}
	if info.NumberOfLinks != 1 {
		return fmt.Errorf("%s link count is %d, want 1", label, info.NumberOfLinks)
	}
	return validateSecureWindowsACL(handle, label)
}

func validateTrustedReadOnlyFile(file *os.File, _ os.FileInfo, label string) error {
	defer func() { runtime.KeepAlive(file) }()
	handle := windows.Handle(file.Fd())
	_, info, err := windowsHandleIdentity(handle)
	if err != nil {
		return fmt.Errorf("stat %s: %w", label, err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%s must be a non-reparse regular file", label)
	}
	if info.NumberOfLinks != 1 {
		return fmt.Errorf("%s link count is %d, want 1", label, info.NumberOfLinks)
	}
	return validateTrustedWindowsACL(handle, label, false)
}

// Windows security attributes are read from the retained handle above. The
// namespace entry contributes only shape and identity continuity checks.
func validateRegularEntry(info os.FileInfo, label string, _ func(*os.File, os.FileInfo, string) error) error {
	return validateRegularEntryShape(info, label)
}
