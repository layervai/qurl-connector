//go:build !windows

package agentstate

// tpmParentOrder prefers the deterministic transient SRK: outside Windows,
// owner authorization is normally empty.
var tpmParentOrder = []tpmParent{tpmParentTransientECCSRK, tpmParentPersistentSRK}
