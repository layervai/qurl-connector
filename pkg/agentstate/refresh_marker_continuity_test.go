//go:build darwin || linux

package agentstate

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/layervai/qurl-connector/internal/pinnedfs"
)

func TestRegistrationRefreshMarkerRejectsHardLinkAndPostReadReplacement(t *testing.T) {
	t.Run("hard link", func(t *testing.T) {
		dir := refreshMarkerTestDir(t)
		if err := RequestRegistrationRefresh(dir, "hard-link"); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(markerPathFor(dir), filepath.Join(dir, "marker-alias")); err != nil {
			t.Fatal(err)
		}
		if _, present, err := LoadRegistrationRefreshMarker(dir); err == nil || present || !strings.Contains(err.Error(), "link count") {
			t.Fatalf("hard-linked marker = present %v err %v, want link-count rejection", present, err)
		}
	})

	t.Run("post-read replacement", func(t *testing.T) {
		dir := refreshMarkerTestDir(t)
		if err := RequestRegistrationRefresh(dir, "replace"); err != nil {
			t.Fatal(err)
		}
		original := beforeRefreshMarkerPostReadValidation
		t.Cleanup(func() { beforeRefreshMarkerPostReadValidation = original })
		beforeRefreshMarkerPostReadValidation = func(*pinnedfs.Directory) {
			beforeRefreshMarkerPostReadValidation = original
			path := markerPathFor(dir)
			if err := os.Rename(path, path+".old"); err != nil {
				t.Error(err)
				return
			}
			if err := os.WriteFile(path, []byte(`{"replacement":true}`), pubMode); err != nil {
				t.Error(err)
			}
		}
		if _, present, err := LoadRegistrationRefreshMarker(dir); err == nil || present || !strings.Contains(err.Error(), "matches") {
			t.Fatalf("replaced marker = present %v err %v, want descriptor-entry rejection", present, err)
		}
	})
}

func TestRegistrationRefreshMarkerTempSubstitutionJoinsCleanupFailures(t *testing.T) {
	dir := refreshMarkerTestDir(t)
	validationErr := errors.New("injected temporary substitution")
	closeErr := errors.New("injected temporary close failure")
	removeErr := errors.New("injected temporary cleanup failure")

	originalValidation := beforeRefreshMarkerTempValidation
	originalClose := closeRefreshMarkerFile
	originalRemove := removeRefreshMarkerTemp
	t.Cleanup(func() {
		beforeRefreshMarkerTempValidation = originalValidation
		closeRefreshMarkerFile = originalClose
		removeRefreshMarkerTemp = originalRemove
	})
	beforeRefreshMarkerTempValidation = func(_ *pinnedfs.Directory, name string) {
		path := filepath.Join(dir, name)
		if err := os.Chmod(path, 0o600); err != nil {
			t.Error(err)
		}
	}
	closeRefreshMarkerFile = func(file *os.File) error {
		return errors.Join(file.Close(), closeErr)
	}
	removeRefreshMarkerTemp = func(namespace *pinnedfs.Directory, name string) error {
		return errors.Join(namespace.Remove(name), removeErr)
	}
	err := RequestRegistrationRefresh(dir, validationErr.Error())
	if err == nil || !strings.Contains(err.Error(), "mode is 0600") || !errors.Is(err, closeErr) || !errors.Is(err, removeErr) {
		t.Fatalf("temp substitution cleanup error = %v, want validation + joined close/remove failures", err)
	}
	if _, statErr := os.Lstat(markerPathFor(dir)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed marker commit published canonical marker: %v", statErr)
	}
}
