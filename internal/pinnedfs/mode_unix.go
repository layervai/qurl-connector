//go:build darwin || linux

package pinnedfs

import "os"

func privateModeMatches(info os.FileInfo, mode os.FileMode) bool {
	return info != nil && info.Mode().Perm() == mode.Perm()
}
