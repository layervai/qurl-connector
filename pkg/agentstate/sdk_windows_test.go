//go:build windows

package agentstate

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	qurl "github.com/layervai/qurl-go/qurl"

	"github.com/layervai/qurl-connector/internal/pinnedfs"
)

func TestWindowsSDKStoreProtectedWriterRoundTripAndContinuity(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "qurl", "connector")
	t.Setenv(EnvKeyProvider, KeyProviderFile)
	owner, store := openSDKStoreForTest(t, dir, "agent-windows")
	want := &qurl.AgentState{
		AgentID:       "agent-windows",
		PrivateKeyB64: "private-secret",
		PublicKeyB64:  "public",
		DeviceAPIKey:  "device-secret",
	}
	if err := store.SaveAgentState(context.Background(), want); err != nil {
		t.Fatalf("save Windows SDK state: %v", err)
	}
	loaded, err := store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatalf("load Windows SDK state: %v", err)
	}
	if !reflect.DeepEqual(loaded, want) {
		t.Fatalf("Windows SDK state = %#v, want %#v", loaded, want)
	}
	if err := owner.ValidateContinuity(); err != nil {
		t.Fatalf("validate Windows SDK store continuity: %v", err)
	}

	namespace, err := pinnedfs.OpenPrivate(dir, 0o700)
	if err != nil {
		t.Fatalf("open Windows SDK state namespace through Connector validator: %v", err)
	}
	defer namespace.Close()
	file, err := namespace.OpenFile(AgentStateFile, os.O_RDONLY|pinnedfs.SafeOpenFlags(), 0)
	if err != nil {
		t.Fatalf("open qurl-go Windows state through Connector validator: %v", err)
	}
	defer file.Close()
	if _, err := pinnedfs.ValidateRegularFile(namespace, AgentStateFile, file, "qurl-go Windows agent state", 0o600); err != nil {
		t.Fatalf("validate qurl-go Windows protected ACL: %v", err)
	}
}
