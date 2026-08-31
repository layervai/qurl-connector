package pinnedfs

import "os"

// PrivateModeMatches reports whether one stat snapshot represents the private
// mode requested by a caller. Windows permissions are proved from the stable
// handle ACL by ValidateRegularFile and directory validation, not FileMode.
func PrivateModeMatches(info os.FileInfo, mode os.FileMode) bool {
	return privateModeMatches(info, mode)
}
