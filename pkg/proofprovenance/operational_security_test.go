//go:build !windows

package proofprovenance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStrictOperationalProvenanceRejectsSymlinkInputs(t *testing.T) {
	t.Run("deployment manifest", func(t *testing.T) {
		fixture := newOperationalTestFixture(t)
		link := filepath.Join(t.TempDir(), "deployment-link.json")
		if err := os.Symlink(os.Getenv(envDeploymentManifestPath), link); err != nil {
			t.Fatal(err)
		}
		t.Setenv(envDeploymentManifestPath, link)
		err := Record(
			fixture.hub,
			fixture.binding("cell0", 1, 1, time.Now().UTC().Add(time.Hour)),
			BoundaryRegistration,
		)
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("symlink manifest error = %v", err)
		}
	})

	t.Run("existing sidecar", func(t *testing.T) {
		fixture := newOperationalTestFixture(t)
		binding := fixture.binding("cell0", 1, 1, time.Now().UTC().Add(time.Hour))
		if err := Record(
			fixture.hub, binding, BoundaryRegistration,
		); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(t.TempDir(), "operational-target.json")
		if err := os.Rename(fixture.outputPath, target); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, fixture.outputPath); err != nil {
			t.Fatal(err)
		}
		err := Record(
			fixture.hub, binding, BoundaryWarmOpen,
		)
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("symlink sidecar error = %v", err)
		}
	})
}

func TestStrictOperationalProvenanceRejectsUnsafeOutputParent(t *testing.T) {
	t.Run("non-private mode", func(t *testing.T) {
		fixture := newOperationalTestFixture(t)
		parent := filepath.Dir(fixture.outputPath)
		if err := os.Chmod(parent, 0o755); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.Chmod(parent, 0o700); err != nil {
				t.Errorf("restore output parent mode: %v", err)
			}
		})

		err := Record(
			fixture.hub,
			fixture.binding("cell0", 1, 1, time.Now().UTC().Add(time.Hour)),
			BoundaryRegistration,
		)
		if err == nil || !strings.Contains(err.Error(), "parent mode is 0755, want 0700") {
			t.Fatalf("non-private parent error = %v", err)
		}
		if _, statErr := os.Stat(fixture.outputPath); !os.IsNotExist(statErr) {
			t.Fatalf("output exists after rejected parent: %v", statErr)
		}
	})

	t.Run("symlink", func(t *testing.T) {
		fixture := newOperationalTestFixture(t)
		targetParent := t.TempDir()
		linkParent := filepath.Join(t.TempDir(), "operational-parent")
		if err := os.Symlink(targetParent, linkParent); err != nil {
			t.Fatal(err)
		}
		outputPath := filepath.Join(linkParent, "operational.json")
		t.Setenv(envStrictOperationalProvenancePath, outputPath)

		err := Record(
			fixture.hub,
			fixture.binding("cell0", 1, 1, time.Now().UTC().Add(time.Hour)),
			BoundaryRegistration,
		)
		if err == nil || !strings.Contains(err.Error(), "parent is not a real directory") {
			t.Fatalf("symlink parent error = %v", err)
		}
		if _, statErr := os.Stat(filepath.Join(targetParent, "operational.json")); !os.IsNotExist(statErr) {
			t.Fatalf("output exists through rejected symlink parent: %v", statErr)
		}
	})
}
