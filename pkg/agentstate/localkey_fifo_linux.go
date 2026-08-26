//go:build linux

package agentstate

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

func validateAnonymousLocalKeyFIFO(fd int, _ *syscall.Stat_t) error {
	target, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil {
		return fmt.Errorf("verify inherited FIFO anonymity: %w", err)
	}
	if !strings.HasPrefix(target, "pipe:[") || !strings.HasSuffix(target, "]") {
		return fmt.Errorf("inherited FIFO is named, not an anonymous pipe")
	}
	return nil
}
