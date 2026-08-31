//go:build !darwin && !linux && !windows

package pinnedfs

func SafeOpenFlags() int {
	return 0
}
