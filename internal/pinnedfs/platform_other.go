//go:build !darwin && !linux && !windows

package pinnedfs

import (
	"fmt"
	"runtime"
)

func requireSupportedPlatform() error {
	return fmt.Errorf("%w: %s", ErrUnsupported, runtime.GOOS)
}
