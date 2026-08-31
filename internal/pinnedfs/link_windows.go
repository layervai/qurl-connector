//go:build windows

package pinnedfs

import (
	"fmt"
	"os"
)

func RequireSingleLinkInfo(_ os.FileInfo, label string) error {
	return fmt.Errorf("inspect link count for %s: stable Windows handle required", label)
}
