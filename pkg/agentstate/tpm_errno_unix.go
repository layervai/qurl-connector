//go:build unix

package agentstate

import (
	"errors"
	"syscall"
)

// tpmOpenTransient reports an open failure worth retrying: a busy device or an
// interrupted open.
func tpmOpenTransient(err error) bool {
	return errors.Is(err, syscall.EBUSY) || errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR)
}
