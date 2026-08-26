//go:build darwin

package agentstate

import (
	"fmt"
	"syscall"
)

func validateAnonymousLocalKeyFIFO(_ int, stat *syscall.Stat_t) error {
	// Darwin anonymous pipes report st_dev=0. A filesystem FIFO retains the
	// containing filesystem's device id even after it is unlinked.
	if stat.Dev != 0 {
		return fmt.Errorf("inherited FIFO is named, not an anonymous pipe")
	}
	return nil
}
