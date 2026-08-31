//go:build !darwin && !linux && !windows

package agentstate

import (
	"errors"
	"testing"

	"github.com/layervai/qurl-connector/internal/pinnedfs"
)

func TestNewSDKStoreFailsClosedOnUnsupportedPlatform(t *testing.T) {
	if store, err := NewSDKStore("state", ""); store != nil || !errors.Is(err, pinnedfs.ErrUnsupported) {
		t.Fatalf("NewSDKStore = (%T, %v), want nil and ErrUnsupported", store, err)
	}
	if reader, err := OpenSDKStateReader("state", ""); reader != nil || !errors.Is(err, pinnedfs.ErrUnsupported) {
		t.Fatalf("OpenSDKStateReader = (%T, %v), want nil and ErrUnsupported", reader, err)
	}
}
