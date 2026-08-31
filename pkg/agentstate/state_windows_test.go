//go:build windows

package agentstate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWindowsDefaultStateDirUsesLocalAppData(t *testing.T) {
	base := filepath.Join(t.TempDir(), "LocalAppData")
	t.Setenv("LOCALAPPDATA", base)
	want := filepath.Join(base, xdgStateSubdir)
	if got := windowsDefaultStateDir(); got != want {
		t.Fatalf("windowsDefaultStateDir = %q, want %q", got, want)
	}
}

func TestWindowsDefaultStateDirRejectsRelativeLocalAppData(t *testing.T) {
	t.Setenv("LOCALAPPDATA", filepath.Join("relative", "LocalAppData"))
	if got := windowsDefaultStateDir(); got != "" {
		t.Fatalf("windowsDefaultStateDir with relative LocalAppData = %q, want empty", got)
	}
}

func TestWindowsResolveDirWithoutOverrideUsesNativeDefault(t *testing.T) {
	clearStateDirEnv(t)
	if DefaultStateDir == "" {
		t.Fatal("Windows default state directory is empty")
	}
	if !filepath.IsAbs(DefaultStateDir) {
		t.Fatalf("Windows default state directory = %q, want an absolute path", DefaultStateDir)
	}
	if strings.Contains(filepath.ToSlash(strings.ToLower(DefaultStateDir)), "/var/lib/") {
		t.Fatalf("Windows default state directory retained a Unix system path: %q", DefaultStateDir)
	}
	if got := ResolveDir(""); got != DefaultStateDir {
		t.Fatalf("ResolveDir without override = %q, want Windows default %q", got, DefaultStateDir)
	}
	base, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(base, xdgStateSubdir)
	if DefaultStateDir != want {
		t.Fatalf("Windows default state directory = %q, want %q", DefaultStateDir, want)
	}
}
