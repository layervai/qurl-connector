//go:build linux

package agentstate

import (
	"errors"
	"syscall"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

// linuxTPMResourceManager is the kernel's in-kernel resource manager. The raw
// /dev/tpm0 is deliberately not used: it is single-open, and transient
// handles left by a crashed process would leak into every other user.
const linuxTPMResourceManager = "/dev/tpmrm0"

func openSystemTPM() (transport.TPMCloser, error) {
	return linuxtpm.Open(linuxTPMResourceManager)
}

// tpmParentOrder prefers the deterministic transient SRK: Linux owner
// authorization is normally empty.
var tpmParentOrder = []tpmParent{tpmParentTransientECCSRK, tpmParentPersistentSRK}

// tpmOpenTransient reports an open failure worth retrying: a busy device or an
// interrupted open.
func tpmOpenTransient(err error) bool {
	return errors.Is(err, syscall.EBUSY) || errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR)
}
