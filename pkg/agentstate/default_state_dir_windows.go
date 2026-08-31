//go:build windows

package agentstate

import (
	"os"
	"path/filepath"
	"strings"
)

// DefaultStateDir is the native per-user Windows state directory. Windows has
// no Unix-style system state root; LocalAppData is the non-roaming location
// for durable machine-local application state.
var DefaultStateDir = windowsDefaultStateDir()

func windowsDefaultStateDir() string {
	base, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	base = strings.TrimSpace(base)
	if base == "" || !filepath.IsAbs(base) {
		return ""
	}
	return filepath.Join(base, xdgStateSubdir)
}
