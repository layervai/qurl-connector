//go:build darwin || linux

package pinnedfs

import (
	"os"
	"strings"
	"testing"
)

func TestUnixRegularEntryAppliesFullPrivateFilePolicy(t *testing.T) {
	path := t.TempDir() + string(os.PathSeparator) + "state.json"
	if err := os.WriteFile(path, []byte("state"), 0o644); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	validate := func(file *os.File, current os.FileInfo, label string) error {
		return validatePrivateRegularFile(file, current, label, 0o600, true)
	}
	if err := validateRegularEntry(info, "Unix state entry", validate); err == nil || !strings.Contains(err.Error(), "mode is 0644, want 0600") {
		t.Fatalf("validateRegularEntry error = %v, want full entry-side mode rejection", err)
	}
}
