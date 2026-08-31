//go:build !darwin && !linux && !windows

package pinnedfs

import "os"

func privateModeMatches(_ os.FileInfo, _ os.FileMode) bool { return false }
