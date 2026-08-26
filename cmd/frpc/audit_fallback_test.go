package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/layervai/qurl-connector/pkg/agentstate"
)

// TestResolveAuditFilePathFallsBackWhenSystemPathUnwritable covers F7: when the
// preferred (default /var/log/layerv) audit directory cannot be created — the
// common non-root case — the connector redirects audit to a user-writable path
// under the resolved state directory instead of silently disabling audit.
func TestResolveAuditFilePathFallsBackWhenSystemPathUnwritable(t *testing.T) {
	// Pin ResolveDir("") deterministically regardless of the test uid: the
	// explicit QURL_CONNECTOR_STATE_DIR override wins over the root/XDG branch.
	stateDir := filepath.Join(t.TempDir(), "state")
	t.Setenv(agentstate.EnvStateDirPrimary, stateDir)

	t.Run("uses the preferred path when its parent is creatable", func(t *testing.T) {
		writable := t.TempDir()
		preferred := filepath.Join(writable, "custom", "audit.log")
		got, usedFallback := resolveAuditFilePath(preferred)
		if usedFallback {
			t.Fatalf("usedFallback = true for a writable preferred path %q", preferred)
		}
		if got != preferred {
			t.Fatalf("resolved path = %q, want the preferred path %q", got, preferred)
		}
	})

	t.Run("falls back under the state dir when the preferred parent is uncreatable", func(t *testing.T) {
		// A regular file stands in for an unwritable/unroutable parent: MkdirAll
		// through a non-directory component fails deterministically without
		// needing root or a real /var/log denial.
		blocker := filepath.Join(t.TempDir(), "blocker")
		if err := os.WriteFile(blocker, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		preferred := filepath.Join(blocker, "nested", "audit.log")

		got, usedFallback := resolveAuditFilePath(preferred)
		if !usedFallback {
			t.Fatalf("usedFallback = false for an uncreatable preferred path %q", preferred)
		}
		want := filepath.Join(agentstate.ResolveDir(""), "audit", "audit.log")
		if got != want {
			t.Fatalf("fallback path = %q, want %q under the resolved state dir", got, want)
		}
		if got != filepath.Join(stateDir, "audit", "audit.log") {
			t.Fatalf("fallback path = %q, want it rooted at the configured state dir %q", got, stateDir)
		}
	})
}
