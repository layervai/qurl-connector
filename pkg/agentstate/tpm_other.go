//go:build !linux && !windows

package agentstate

import (
	"errors"

	"github.com/google/go-tpm/tpm2/transport"
)

// openSystemTPM reports no TPM. macOS has none; its Secure Enclave is a
// different interface.
func openSystemTPM() (transport.TPMCloser, error) {
	return nil, errors.New("no TPM 2.0 interface on this platform")
}
