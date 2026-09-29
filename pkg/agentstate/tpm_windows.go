//go:build windows

package agentstate

import (
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/windowstpm"
)

// openSystemTPM opens the TPM 2.0 through the TPM Base Services resource
// manager (tbs.dll).
func openSystemTPM() (transport.TPMCloser, error) {
	return windowstpm.Open()
}
