package share

import (
	"path/filepath"
	"testing"

	"github.com/layervai/qurl-connector/internal/pinnedfs"
)

func secureNativeStateDirForTest(t *testing.T) string {
	t.Helper()
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(parent, "state")
	namespace, err := pinnedfs.EnsurePrivate(dir, 0o700)
	if err != nil {
		t.Fatalf("create secure native-state test directory: %v", err)
	}
	if err := namespace.Close(); err != nil {
		t.Fatalf("close secure native-state test directory: %v", err)
	}
	return dir
}
