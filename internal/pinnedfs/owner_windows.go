//go:build windows

package pinnedfs

import (
	"fmt"
	"os"
)

func validateCurrentOwner(_ os.FileInfo, label string) error {
	return fmt.Errorf("inspect owner for %s: stable Windows handle required", label)
}

func RequireCurrentOwnerInfo(_ os.FileInfo, label string) error {
	return fmt.Errorf("inspect owner for %s: stable Windows handle required", label)
}
