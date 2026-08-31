//go:build windows

package pinnedfs

// SafeOpenFlags is zero because os.Root and openPinnedFile use NT
// handle-relative opens with no reparse traversal on Windows.
func SafeOpenFlags() int { return 0 }
