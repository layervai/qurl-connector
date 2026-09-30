//go:build windows

package agentstate

import (
	"errors"
	"syscall"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/windowstpm"
	"github.com/google/go-tpm/tpmutil/tbs"
)

// openSystemTPM opens the TPM 2.0 through the TPM Base Services resource
// manager (tbs.dll).
func openSystemTPM() (transport.TPMCloser, error) {
	return windowstpm.Open()
}

// tpmParentOrder prefers the SRK Windows provisions: Windows discards owner
// authorization, so a transient SRK under the owner hierarchy is refused.
var tpmParentOrder = []tpmParent{tpmParentPersistentSRK, tpmParentTransientECCSRK}

// tpmOpenTransient reports an open failure worth retrying: TPM Base Services
// still starting or stopped, out of contexts, or a canceled command. A missing
// TPM (TBS_E_TPM_NOT_FOUND) and other results are structural.
func tpmOpenTransient(err error) bool {
	var tbsErr tbs.Error
	if !errors.As(err, &tbsErr) {
		return errors.Is(err, syscall.EBUSY) || errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR)
	}
	switch tbsErr {
	case tbs.ErrServiceStartPending, tbs.ErrServiceNotRunning, tbs.ErrTooManyTBSContexts, tbs.ErrCommandCanceled:
		return true
	default:
		return false
	}
}
