//go:build windows

package pinnedfs

import "os"

func privateModeMatches(info os.FileInfo, _ os.FileMode) bool { return info != nil }
