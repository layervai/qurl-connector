//go:build windows

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverUsesNativeWindowsHome(t *testing.T) {
	nativeHome := t.TempDir()
	shellHome := t.TempDir()
	t.Setenv("USERPROFILE", nativeHome)
	t.Setenv("HOME", shellHome)
	t.Setenv("HOMEDRIVE", "")
	t.Setenv("HOMEPATH", "")

	configDir := filepath.Join(nativeHome, UserConfigDir)
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(configDir, yamlConfigName)
	if err := os.WriteFile(want, []byte("server:\n  addr: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	emptyCWD := t.TempDir()
	oldCWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldCWD) })
	if err := os.Chdir(emptyCWD); err != nil {
		t.Fatal(err)
	}

	got, err := Discover("")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("Discover = %q, want native Windows home config %q", got, want)
	}
}
