//go:build unix && !darwin && !linux

package agentstate

import (
	"fmt"
	"runtime"
	"syscall"
)

func validateAnonymousLocalKeyFIFO(_ int, _ *syscall.Stat_t) error {
	return fmt.Errorf("anonymous inherited FIFO verification is unsupported on %s", runtime.GOOS)
}
