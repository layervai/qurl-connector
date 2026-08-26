//go:build !darwin && !linux

package agentstate

// systemStateDirCreatable assumes the system default is usable on platforms
// without a writability probe. The Connector's pinned-filesystem layer only
// supports darwin and linux (pinnedfs.requireSupportedPlatform), so this branch
// is effectively unreachable at runtime; it exists only to keep the package
// buildable everywhere and preserves the pre-fallback behavior (always the
// system default) on such platforms.
func systemStateDirCreatable() bool { return true }
