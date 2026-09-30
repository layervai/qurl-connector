//go:build !linux && !windows

package agentstate

import (
	"errors"
	"syscall"

	"github.com/google/go-tpm/tpm2/transport"
)

// openSystemTPM reports no TPM. macOS has none; its Secure Enclave is a
// different interface.
func openSystemTPM() (transport.TPMCloser, error) {
	return nil, errors.New("no TPM 2.0 interface on this platform")
}

var tpmParentOrder = []tpmParent{tpmParentTransientECCSRK, tpmParentPersistentSRK}

// tpmOpenTransient reports an open failure worth retrying: a busy device or an
// interrupted open.
func tpmOpenTransient(err error) bool {
	return errors.Is(err, syscall.EBUSY) || errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR)
}
