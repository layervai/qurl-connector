//go:build darwin || linux

package pinnedfs

import (
	"os"
	"path/filepath"
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

func TestUnixRegularFileRejectsMutationBeforeFinalDescriptorSnapshot(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, string)
		want   string
	}{
		{
			name: "hard link",
			mutate: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Link(path, path+".alias"); err != nil {
					t.Fatal(err)
				}
			},
			want: "link count is 2",
		},
		{
			name: "mode change",
			mutate: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
			},
			want: "mode is 0644, want 0600",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := filepath.Join(realTempDir(t), "private")
			namespace, err := EnsurePrivate(dir, 0o700)
			if err != nil {
				t.Fatal(err)
			}
			defer namespace.Close()

			const name = "state.json"
			path := filepath.Join(dir, name)
			file, err := namespace.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL|SafeOpenFlags(), 0o600)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			if err := file.Chmod(0o600); err != nil {
				t.Fatal(err)
			}

			original := beforeRegularFileFinalDescriptorValidation
			mutated := false
			beforeRegularFileFinalDescriptorValidation = func(*Directory, string, *os.File) {
				if mutated {
					return
				}
				mutated = true
				tt.mutate(t, path)
			}
			t.Cleanup(func() { beforeRegularFileFinalDescriptorValidation = original })

			if _, err := ValidateRegularFile(namespace, name, file, "state", 0o600); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("ValidateRegularFile error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestUnixRegularFileRejectsMutationBeforeFinalEntrySnapshot(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, string)
		want   string
	}{
		{
			name: "hard link",
			mutate: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Link(path, path+".alias"); err != nil {
					t.Fatal(err)
				}
			},
			want: "final entry link count is 2",
		},
		{
			name: "mode change",
			mutate: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
			},
			want: "final entry mode is 0644, want 0600",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := filepath.Join(realTempDir(t), "private")
			namespace, err := EnsurePrivate(dir, 0o700)
			if err != nil {
				t.Fatal(err)
			}
			defer namespace.Close()

			const name = "state.json"
			path := filepath.Join(dir, name)
			file, err := namespace.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL|SafeOpenFlags(), 0o600)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			if err := file.Chmod(0o600); err != nil {
				t.Fatal(err)
			}

			original := beforeRegularFileFinalEntryValidation
			mutated := false
			beforeRegularFileFinalEntryValidation = func(*Directory, string, *os.File) {
				if mutated {
					return
				}
				mutated = true
				tt.mutate(t, path)
			}
			t.Cleanup(func() { beforeRegularFileFinalEntryValidation = original })

			if _, err := ValidateRegularFile(namespace, name, file, "state", 0o600); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("ValidateRegularFile error = %v, want %q", err, tt.want)
			}
		})
	}
}
