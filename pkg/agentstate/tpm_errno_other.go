//go:build !unix && !windows

package agentstate

// tpmOpenTransient reports no transient open failures on platforms without a
// TPM transport: openSystemTPM there fails structurally.
func tpmOpenTransient(error) bool { return false }
