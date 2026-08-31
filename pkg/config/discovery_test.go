package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscover_ExplicitPath(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "custom.yaml")
	if err := os.WriteFile(p, []byte("server:\n  addr: x\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := Discover(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != p {
		t.Errorf("path = %q, want %q", got, p)
	}
}

func TestDiscover_ExplicitPathMissing(t *testing.T) {
	_, err := Discover("/nonexistent/file.yaml")
	if err == nil {
		t.Fatal("expected error for missing explicit path")
	}
}

func TestDiscover_CWD(t *testing.T) {
	dir := t.TempDir()
	// Resolve symlinks so the comparison works on macOS where /var -> /private/var.
	dir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, yamlConfigName)
	if err := os.WriteFile(p, []byte("server:\n  addr: x\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Temporarily change CWD.
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig) })

	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	got, err := Discover("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != p {
		t.Errorf("path = %q, want %q", got, p)
	}
}

func TestDiscover_UserConfigDir(t *testing.T) {
	// Use a temp dir as a fake home.
	home := t.TempDir()
	setTestUserHome(t, home)

	configDir := filepath.Join(home, UserConfigDir)
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(configDir, yamlConfigName)
	if err := os.WriteFile(p, []byte("server:\n  addr: x\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Make sure CWD does not contain the config.
	emptyDir := t.TempDir()
	orig, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(orig) })
	_ = os.Chdir(emptyDir)

	got, err := Discover("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != p {
		t.Errorf("path = %q, want %q", got, p)
	}
}

func TestDiscover_NothingFound(t *testing.T) {
	// Point CWD and HOME to empty dirs so nothing is found.
	emptyDir := t.TempDir()
	emptyHome := t.TempDir()
	setTestUserHome(t, emptyHome)

	orig, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(orig) })
	_ = os.Chdir(emptyDir)

	_, err := Discover("")
	if err == nil {
		t.Fatal("expected error when no config is found")
	}
}

func setTestUserHome(t *testing.T, home string) {
	t.Helper()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("HOMEDRIVE", "")
	t.Setenv("HOMEPATH", "")
}
