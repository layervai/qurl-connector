//go:build darwin || linux

package pinnedfs

func requireSupportedPlatform() error {
	return nil
}
