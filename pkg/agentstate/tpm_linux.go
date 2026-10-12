//go:build linux

package agentstate

import (
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
