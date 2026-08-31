//go:build !darwin && !linux && !windows

package agentstate

// systemStateDirCreatable assumes the system default is usable on unsupported
// platforms without a writability probe. This keeps those packages buildable;
// the pinned-filesystem layer still rejects their state operations.
func systemStateDirCreatable() bool { return true }
