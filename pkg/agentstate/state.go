// Package agentstate adapts qurl-go's complete native-agent state envelope to
// the Connector's host-volume and cloud-key-provider conventions.
package agentstate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/layervai/qurl-connector/internal/pinnedfs"
)

const (
	StateDEKSize = 32

	// EnvStateDirPrimary is the Connector state-directory override.
	EnvStateDirPrimary = "QURL_CONNECTOR_STATE_DIR"
	EnvAgentID         = "QURL_CONNECTOR_AGENT_ID"

	// xdgStateSubdir is the per-application directory appended to the XDG state
	// base (or ~/.local/state) for the non-root user fallback.
	xdgStateSubdir = "qurl-connector"

	// Pre-native-runtime filenames are retained only so startup can detect and
	// reject an unsafe in-place migration before qurl-go mutates the directory.
	AgentIDFile    = "agent_id"
	PrivateKeyFile = "private_key"
	PublicKeyFile  = "public_key"

	dirMode os.FileMode = 0o700
	pubMode os.FileMode = 0o644
)

// stateDirUsableAtSystemDefault reports whether this process can use the
// platform default. On Unix this is the root-owned system path; on Windows it
// is the current user's LocalAppData path. It is a package var so tests can pin
// either branch; the production value is the platform usability probe
// (systemStateDirCreatable, defined per-GOOS).
var stateDirUsableAtSystemDefault = systemStateDirCreatable

// ResolveDir resolves the native-agent state directory. Resolution order, most
// specific first:
//
//  1. explicit override argument (e.g. a future --state-dir flag)
//  2. QURL_CONNECTOR_STATE_DIR
//  3. the platform default DefaultStateDir when this process can use it. On
//     Unix this is true for root / service installs AND for a non-root
//     container whose writable state volume is mounted at the system default
//     (the hardened distroless image runs as UID 65532 on a read-only rootfs
//     with /var/lib/layerv/agent provided as a writable --volume). On Windows
//     this is the current user's absolute LocalAppData path.
//  4. an XDG user path ($XDG_STATE_HOME/qurl-connector, else
//     ~/.local/state/qurl-connector) only when the system default is not
//     usable — the common non-root developer on a normal filesystem where
//     /var/lib is root-owned.
//
// The Unix decision is writability-driven, not uid-driven: a non-root process
// with a writable system default (the container) must not be pushed onto a
// read-only XDG path, and a non-root developer without one must not be pushed
// onto a root-owned /var path. An operator can always name a path explicitly
// through QURL_CONNECTOR_STATE_DIR to bypass the platform probe.
func ResolveDir(override string) string {
	if dir := absCleanDir(override); dir != "" {
		return dir
	}
	if dir := absCleanDir(os.Getenv(EnvStateDirPrimary)); dir != "" {
		return dir
	}
	if stateDirUsableAtSystemDefault() {
		return DefaultStateDir
	}
	if xdg := xdgStateDir(); xdg != "" {
		return xdg
	}
	// No user-state base and no home directory: keep the platform default rather
	// than an unrooted relative path. The run then fails with a clear error that
	// names the path instead of silently writing under the cwd.
	return DefaultStateDir
}

// absCleanDir trims raw and returns its absolute, cleaned form, or "" when raw
// is blank.
func absCleanDir(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if abs, err := filepath.Abs(raw); err == nil {
		return abs
	}
	return filepath.Clean(raw)
}

// xdgStateDir returns the XDG user state directory for the Connector, or "" when
// neither an absolute XDG_STATE_HOME nor a home directory is available.
func xdgStateDir() string {
	if base := strings.TrimSpace(os.Getenv("XDG_STATE_HOME")); base != "" && filepath.IsAbs(base) {
		return filepath.Join(base, xdgStateSubdir)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	if home = strings.TrimSpace(home); home == "" {
		return ""
	}
	return filepath.Join(home, ".local", "state", xdgStateSubdir)
}

// EnsureDirMode makes dir exist as an owner-only state directory before the
// pinned-filesystem layer validates it. Unix uses mode 0700. Windows creates a
// protected owner/SYSTEM/Administrators ACL atomically for each missing edge.
//
// pinnedfs.EnsurePrivate (and qurl-go's OpenFileAgentState) require the state
// directory to be exactly 0700 and fail closed otherwise ("has mode 0755, want
// 0700"). EnsurePrivate creates a *missing* directory at 0700, but it
// deliberately does not loosen or tighten one that already exists — so a
// directory a user created by hand, or a packaged install left at 0755, would
// make the very first run die on a mode check it never had a chance to satisfy.
//
// On Unix, EnsureDirMode closes that gap by creating and chmodding the final
// directory before pinned validation. Windows is a greenfield contract and
// does not adopt an existing directory with inherited or foreign ACLs; it uses
// pinnedfs.EnsurePrivate for protected creation and exact ACL validation.
func EnsureDirMode(dir string) error {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return errors.New("state directory path is empty")
	}
	if runtime.GOOS == "windows" {
		namespace, err := pinnedfs.EnsurePrivate(dir, dirMode)
		if err != nil {
			return fmt.Errorf("create protected Windows state directory %s: %w; if the directory already exists, stop Connector, move it aside, and retry so Connector can create the protected directory", dir, err)
		}
		if err := namespace.Close(); err != nil {
			return fmt.Errorf("close protected Windows state directory %s: %w", dir, err)
		}
		return nil
	}
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return fmt.Errorf("create state directory %s: %w", dir, err)
	}
	if err := os.Chmod(dir, dirMode); err != nil {
		return fmt.Errorf("restrict state directory %s to owner-only %#o: %w", dir, dirMode, err)
	}
	return nil
}
