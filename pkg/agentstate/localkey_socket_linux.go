//go:build linux

package agentstate

import (
	"syscall"
	"unsafe"
)

func isAnonymousLocalKeySocketAddress(fd int, peer bool, name string) bool {
	// Linux's syscall.SockaddrUnix decoder rewrites a leading NUL to "@"
	// without consulting the returned sockaddr length. Both an unbound
	// socketpair endpoint (socklen=2, family only) and an explicitly bound empty
	// abstract address (socklen=3) therefore appear as "@". Read the kernel's
	// actual length so only the former capability is accepted.
	if name != "" && name != "@" {
		return false
	}
	var raw syscall.RawSockaddrAny
	length := uint32(unsafe.Sizeof(raw))
	trap := uintptr(syscall.SYS_GETSOCKNAME)
	if peer {
		trap = uintptr(syscall.SYS_GETPEERNAME)
	}
	_, _, errno := syscall.Syscall(
		trap,
		uintptr(fd),
		uintptr(unsafe.Pointer(&raw)),
		uintptr(unsafe.Pointer(&length)),
	)
	return errno == 0 && length == 2
}
