//go:build windows

package pinnedfs

import (
	"fmt"
	"os"
)

func validateTrustedDirectory(_ os.FileInfo, label string, _ bool) error {
	return fmt.Errorf("inspect trust attributes for %s: stable Windows handle required", label)
}

func validateTrustedReadOnlyInfo(_ os.FileInfo, label string) error {
	return fmt.Errorf("inspect trust attributes for %s: stable Windows handle required", label)
}
