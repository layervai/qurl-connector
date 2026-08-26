//go:build !unix

package pinnedfs

import "os"

func validateCurrentOwner(_ os.FileInfo, _ string) error {
	return nil
}

// RequireCurrentOwnerInfo is unreachable because unsupported platforms fail at
// the pinned-directory entrypoint.
func RequireCurrentOwnerInfo(_ os.FileInfo, _ string) error {
	return nil
}
