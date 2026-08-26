//go:build darwin || linux

package pinnedfs

import "golang.org/x/sys/unix"

// SafeOpenFlags prevents final-component symlink and special-file blocking.
func SafeOpenFlags() int {
	return unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
}
