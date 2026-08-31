//go:build !darwin && !linux && !windows

package pinnedfs

import (
	"errors"
	"testing"
)

func TestDirectoryEntrypointsFailClosedOnUnsupportedPlatform(t *testing.T) {
	if dir, err := Open("."); dir != nil || !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Open = (%v, %v), want nil and ErrUnsupported", dir, err)
	}
	if dir, err := EnsurePrivate("state", 0o700); dir != nil || !errors.Is(err, ErrUnsupported) {
		t.Fatalf("EnsurePrivate = (%v, %v), want nil and ErrUnsupported", dir, err)
	}
}
