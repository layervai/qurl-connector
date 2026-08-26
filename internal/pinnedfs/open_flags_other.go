//go:build !darwin && !linux

package pinnedfs

func SafeOpenFlags() int {
	return 0
}
