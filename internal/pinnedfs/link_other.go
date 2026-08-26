//go:build !unix

package pinnedfs

import (
	"fmt"
	"os"
)

func RequireSingleLinkInfo(_ os.FileInfo, label string) error {
	return fmt.Errorf("cannot prove single-link identity for %s on this platform", label)
}
