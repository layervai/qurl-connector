//go:build windows

package agentstate

// systemStateDirCreatable reports whether Windows supplied an absolute
// LocalAppData directory. EnsureDirMode performs the protected ACL creation.
func systemStateDirCreatable() bool { return DefaultStateDir != "" }
