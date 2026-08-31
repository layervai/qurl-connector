package agentstate

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	qurl "github.com/layervai/qurl-go/qurl"

	"github.com/layervai/qurl-connector/internal/pinnedfs"
)

type testStateKeyProvider struct {
	name       string
	sealCtx    map[string]string
	unsealSeen bool
}

type blockingStateKeyProvider struct {
	testStateKeyProvider
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

type blockingContinuityStore struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *blockingContinuityStore) LoadAgentState(context.Context) (*qurl.AgentState, error) {
	return nil, errors.New("unexpected LoadAgentState")
}

func (s *blockingContinuityStore) SaveAgentState(context.Context, *qurl.AgentState) error {
	return errors.New("unexpected SaveAgentState")
}

func (s *blockingContinuityStore) ValidateContinuity() error { return nil }

func (s *blockingContinuityStore) Close() error {
	s.once.Do(func() { close(s.entered) })
	<-s.release
	return nil
}

func (p *blockingStateKeyProvider) Seal(ctx context.Context, plaintext []byte, binding map[string]string) (SealedPrivateKey, error) {
	p.once.Do(func() { close(p.entered) })
	select {
	case <-ctx.Done():
		return SealedPrivateKey{}, ctx.Err()
	case <-p.release:
	}
	return p.testStateKeyProvider.Seal(ctx, plaintext, binding)
}

type deadlineProbe struct {
	hasDeadline bool
	deadline    time.Time
}

type deadlineProbeProvider struct {
	seen chan deadlineProbe
}

func (p *deadlineProbeProvider) Name() string { return KeyProviderAWSKMS }

func (p *deadlineProbeProvider) wait(ctx context.Context) error {
	deadline, ok := ctx.Deadline()
	p.seen <- deadlineProbe{hasDeadline: ok, deadline: deadline}
	<-ctx.Done()
	return ctx.Err()
}

func (p *deadlineProbeProvider) Seal(ctx context.Context, _ []byte, _ map[string]string) (SealedPrivateKey, error) {
	return SealedPrivateKey{}, p.wait(ctx)
}

func (p *deadlineProbeProvider) Unseal(ctx context.Context, _ SealedPrivateKey) ([]byte, error) {
	return nil, p.wait(ctx)
}

func (p *testStateKeyProvider) Name() string { return p.name }

func (p *testStateKeyProvider) Seal(_ context.Context, plaintext []byte, binding map[string]string) (SealedPrivateKey, error) {
	p.sealCtx = cloneStringMap(binding)
	return SealedPrivateKey{
		Version: 1, Provider: p.name, KeyID: "test-key",
		CiphertextBase64:  base64.StdEncoding.EncodeToString(plaintext),
		EncryptionContext: cloneStringMap(binding), CreatedAt: "2026-07-17T00:00:00Z",
	}, nil
}

func (p *testStateKeyProvider) Unseal(_ context.Context, sealed SealedPrivateKey) ([]byte, error) {
	p.unsealSeen = true
	return base64.StdEncoding.DecodeString(sealed.CiphertextBase64)
}

func cloneStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func realSDKTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func openSDKStoreForTest(t *testing.T, dir, configuredAgentID string) (*SDKStore, qurl.AgentStateStore) {
	t.Helper()
	owner, err := NewSDKStore(dir, configuredAgentID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := owner.Close(); err != nil {
			t.Errorf("close SDK store: %v", err)
		}
	})
	store, err := owner.Handoff()
	if err != nil {
		t.Fatal(err)
	}
	return owner, store
}

type sdkStateFilesystemSnapshot struct {
	dirMode    os.FileMode
	dirModTime time.Time
	files      map[string]sdkStateFileSnapshot
}

type sdkStateFileSnapshot struct {
	mode    os.FileMode
	size    int64
	modTime time.Time
	digest  [sha256.Size]byte
}

func snapshotSDKStateFilesystem(t *testing.T, dir string) sdkStateFilesystemSnapshot {
	t.Helper()
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := sdkStateFilesystemSnapshot{
		dirMode:    dirInfo.Mode(),
		dirModTime: dirInfo.ModTime(),
		files:      make(map[string]sdkStateFileSnapshot, len(entries)),
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		file := sdkStateFileSnapshot{
			mode:    info.Mode(),
			size:    info.Size(),
			modTime: info.ModTime(),
		}
		if info.Mode().IsRegular() {
			raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			file.digest = sha256.Sum256(raw)
		}
		snapshot.files[entry.Name()] = file
	}
	return snapshot
}

func TestOpenSDKStateReaderReadsWithoutFilesystemMutation(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("read-only pinned SDK state readers are supported on Linux and Darwin")
	}
	tests := []struct {
		name     string
		provider string
		sealed   bool
	}{
		{name: "plaintext", provider: KeyProviderFile},
		{name: "sealed", provider: KeyProviderAWSKMS, sealed: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(EnvKeyProvider, tt.provider)
			if tt.sealed {
				provider := &testStateKeyProvider{name: KeyProviderAWSKMS}
				originalFactory := keyProviderForName
				keyProviderForName = func(name string) (KeyProvider, error) {
					if name != KeyProviderAWSKMS {
						return nil, fmt.Errorf("unexpected provider %q", name)
					}
					return provider, nil
				}
				t.Cleanup(func() { keyProviderForName = originalFactory })
			}

			dir := filepath.Join(realSDKTempDir(t), "state")
			owner, err := NewSDKStore(dir, "agent-read-only")
			if err != nil {
				t.Fatal(err)
			}
			store, err := owner.Handoff()
			if err != nil {
				t.Fatal(err)
			}
			want := &qurl.AgentState{
				AgentID:       "agent-read-only",
				PrivateKeyB64: "private-secret",
				PublicKeyB64:  "public",
				DeviceAPIKey:  "device-secret",
			}
			if err := store.SaveAgentState(context.Background(), want); err != nil {
				t.Fatal(err)
			}
			if err := owner.Close(); err != nil {
				t.Fatal(err)
			}

			before := snapshotSDKStateFilesystem(t, dir)
			reader, err := OpenSDKStateReader(dir, want.AgentID)
			if err != nil {
				t.Fatal(err)
			}
			if _, writable := reader.(qurl.AgentStateStore); writable {
				t.Fatalf("read-only SDK adapter %T exposes AgentStateStore", reader)
			}
			loaded, err := reader.LoadAgentState(context.Background())
			if err != nil {
				_ = reader.Close()
				t.Fatal(err)
			}
			if !reflect.DeepEqual(loaded, want) {
				_ = reader.Close()
				t.Fatalf("read-only state = %#v, want %#v", loaded, want)
			}
			*loaded = qurl.AgentState{}
			if err := reader.Close(); err != nil {
				t.Fatal(err)
			}
			after := snapshotSDKStateFilesystem(t, dir)
			if !reflect.DeepEqual(after, before) {
				t.Fatalf("read-only adapter mutated filesystem:\nbefore=%#v\nafter=%#v", before, after)
			}
		})
	}
}

func TestOpenSDKStateReaderMissingDirectoryDoesNotCreateIt(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("read-only pinned SDK state readers are supported on Linux and Darwin")
	}
	dir := filepath.Join(realSDKTempDir(t), "missing")
	if reader, err := OpenSDKStateReader(dir, ""); reader != nil || err == nil {
		t.Fatalf("OpenSDKStateReader = (%T, %v), want missing-directory error", reader, err)
	}
	if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only adapter created missing state directory: %v", err)
	}
}

func TestSDKStateKeyWrapperBindsCompleteEnvelopeIdentity(t *testing.T) {
	provider := &testStateKeyProvider{name: KeyProviderAWSKMS}
	wrapper := &sdkStateKeyWrapper{provider: provider}
	binding := qurl.AgentStateKeyBinding{
		Purpose: "native-agent-state", EnvelopeVersion: 3,
		ProviderID: KeyProviderAWSKMS, AgentID: "agent-7",
	}
	dek := make([]byte, StateDEKSize)
	for i := range dek {
		dek[i] = byte(i + 1)
	}

	wrapped, err := wrapper.WrapKey(context.Background(), dek, binding)
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	wantContext := map[string]string{
		"purpose": wrappedKeyPurpose + "/native-agent-state", "envelope_version": "3",
		"provider_id": KeyProviderAWSKMS, "agent_id": "agent-7",
	}
	if !reflect.DeepEqual(provider.sealCtx, wantContext) {
		t.Fatalf("authenticated context = %#v, want %#v", provider.sealCtx, wantContext)
	}
	got, err := wrapper.UnwrapKey(context.Background(), wrapped, binding)
	if err != nil {
		t.Fatalf("UnwrapKey: %v", err)
	}
	if !provider.unsealSeen || !reflect.DeepEqual(got, dek) {
		t.Fatalf("unwrapped DEK mismatch")
	}
}

func TestSDKStateKeyWrapperRejectsBindingTamperBeforeProvider(t *testing.T) {
	provider := &testStateKeyProvider{name: KeyProviderAWSKMS}
	wrapper := &sdkStateKeyWrapper{provider: provider}
	binding := qurl.AgentStateKeyBinding{Purpose: "state", EnvelopeVersion: 1, ProviderID: KeyProviderAWSKMS, AgentID: "agent-a"}
	wrapped, err := wrapper.WrapKey(context.Background(), make([]byte, StateDEKSize), binding)
	if err != nil {
		t.Fatal(err)
	}
	provider.unsealSeen = false
	binding.AgentID = "agent-b"
	if _, err := wrapper.UnwrapKey(context.Background(), wrapped, binding); !errors.Is(err, qurl.ErrInvalidWrappedAgentStateKey) {
		t.Fatalf("UnwrapKey error = %v, want ErrInvalidWrappedAgentStateKey", err)
	}
	if provider.unsealSeen {
		t.Fatal("provider was invoked before binding mismatch was rejected")
	}
}

func TestSDKStateKeyWrapperRejectsUnknownInnerVersionBeforeProvider(t *testing.T) {
	provider := &testStateKeyProvider{name: KeyProviderAWSKMS}
	wrapper := &sdkStateKeyWrapper{provider: provider}
	binding := qurl.AgentStateKeyBinding{Purpose: "state", EnvelopeVersion: 1, ProviderID: KeyProviderAWSKMS, AgentID: "agent-a"}
	raw, err := json.Marshal(SealedPrivateKey{
		Version: sealedPrivateKeyVersion + 1, Provider: KeyProviderAWSKMS, KeyID: "test-key",
		CiphertextBase64: "AA==", EncryptionContext: sdkKeyEncryptionContext(binding),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrapper.UnwrapKey(context.Background(), qurl.WrappedAgentStateKey{
		Version: wrappedAgentStateKeyVersion, Ciphertext: raw,
	}, binding); !errors.Is(err, qurl.ErrInvalidWrappedAgentStateKey) {
		t.Fatalf("UnwrapKey error = %v, want ErrInvalidWrappedAgentStateKey", err)
	}
	if provider.unsealSeen {
		t.Fatal("provider was invoked before inner record version was rejected")
	}
}

func TestSDKStateKeyWrapperBoundsProviderOperationsAndPropagatesCancellation(t *testing.T) {
	binding := qurl.AgentStateKeyBinding{Purpose: "state", EnvelopeVersion: 1, ProviderID: KeyProviderAWSKMS, AgentID: "agent-a"}
	wrappedRecord, err := json.Marshal(SealedPrivateKey{
		Version: sealedPrivateKeyVersion, Provider: KeyProviderAWSKMS, KeyID: "test-key",
		CiphertextBase64: "AA==", EncryptionContext: sdkKeyEncryptionContext(binding),
	})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name            string
		call            func(context.Context, *sdkStateKeyWrapper) error
		parentDeadline  time.Duration
		maxSeenDeadline time.Duration
	}{
		{
			name: "seal adds wrapper deadline",
			call: func(ctx context.Context, wrapper *sdkStateKeyWrapper) error {
				_, err := wrapper.WrapKey(ctx, make([]byte, StateDEKSize), binding)
				return err
			},
			maxSeenDeadline: keyProviderTimeout + time.Second,
		},
		{
			name: "unseal preserves earlier caller deadline",
			call: func(ctx context.Context, wrapper *sdkStateKeyWrapper) error {
				_, err := wrapper.UnwrapKey(ctx, qurl.WrappedAgentStateKey{Version: wrappedAgentStateKeyVersion, Ciphertext: wrappedRecord}, binding)
				return err
			},
			parentDeadline: time.Second, maxSeenDeadline: 2 * time.Second,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &deadlineProbeProvider{seen: make(chan deadlineProbe, 1)}
			wrapper := &sdkStateKeyWrapper{provider: provider}
			ctx, cancel := context.WithCancel(context.Background())
			if tt.parentDeadline != 0 {
				ctx, cancel = context.WithTimeout(context.Background(), tt.parentDeadline)
			}
			result := make(chan error, 1)
			go func() { result <- tt.call(ctx, wrapper) }()

			probe := <-provider.seen
			if !probe.hasDeadline {
				t.Fatal("provider context has no deadline")
			}
			if remaining := time.Until(probe.deadline); remaining <= 0 || remaining > tt.maxSeenDeadline {
				t.Fatalf("provider deadline remaining = %v, want within (0, %v]", remaining, tt.maxSeenDeadline)
			}
			cancel()
			if err := <-result; !errors.Is(err, context.Canceled) {
				t.Fatalf("wrapper error = %v, want context.Canceled", err)
			}
		})
	}
}

func TestLegacyArtifactsFindsOnlyPresentPreNativeState(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{PrivateKeyFile, filepath.Join("etc", "server.toml")} {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("legacy"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	found, err := LegacyArtifacts(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{PrivateKeyFile, filepath.Join("etc", "server.toml")}
	if !reflect.DeepEqual(found, want) {
		t.Fatalf("LegacyArtifacts = %v, want %v", found, want)
	}
}

func TestNewSDKStoreFileProviderUsesSingleSDKEnvelope(t *testing.T) {
	dir := filepath.Join(realSDKTempDir(t), "state")
	t.Setenv(EnvKeyProvider, KeyProviderFile)
	_, store := openSDKStoreForTest(t, dir, "")
	if _, ok := store.(*qurl.FileAgentStateStore); !ok {
		t.Fatalf("plaintext handoff type = %T, want *qurl.FileAgentStateStore", store)
	}
	state := qurl.AgentState{AgentID: "agent-a"}
	if err := store.SaveAgentState(context.Background(), &state); err != nil {
		t.Fatal(err)
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("SDK state directory: %v", err)
	}
	if !pinnedfs.PrivateModeMatches(dirInfo, 0o700) {
		t.Fatalf("SDK state directory mode = %#o, want private mode", dirInfo.Mode().Perm())
	}
	stateInfo, err := os.Lstat(filepath.Join(dir, AgentStateFile))
	if err != nil {
		t.Fatalf("SDK state file: %v", err)
	}
	if !stateInfo.Mode().IsRegular() {
		t.Fatalf("SDK state file mode = %v, want regular file", stateInfo.Mode())
	}
	if !pinnedfs.PrivateModeMatches(stateInfo, 0o600) {
		t.Fatalf("SDK state file mode = %#o, want private mode", stateInfo.Mode().Perm())
	}
	for _, legacy := range []string{AgentIDFile, PrivateKeyFile, PublicKeyFile, SealedPrivateKeyFile} {
		if _, err := os.Stat(filepath.Join(dir, legacy)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("legacy %s exists or stat failed: %v", legacy, err)
		}
	}
}

func TestSDKStoreFailsClosedWhenStateNamespaceIsReplaced(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows prevents replacement while the retained directory handle is open")
	}
	parent := realSDKTempDir(t)
	dir := filepath.Join(parent, "state")
	t.Setenv(EnvKeyProvider, KeyProviderFile)
	owner, err := NewSDKStore(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Handoff(); err != nil {
		t.Fatalf("initial Handoff: %v", err)
	}

	displaced := filepath.Join(parent, "state-displaced")
	if err := os.Rename(dir, displaced); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := owner.ValidateContinuity(); !errors.Is(err, qurl.ErrAgentStateContinuity) {
		t.Fatalf("ValidateContinuity after replacement = %v, want ErrAgentStateContinuity", err)
	}
	if store, err := owner.Handoff(); store != nil || !errors.Is(err, qurl.ErrAgentStateContinuity) {
		t.Fatalf("Handoff after replacement = (%T, %v), want nil and ErrAgentStateContinuity", store, err)
	}
	if err := owner.Close(); !errors.Is(err, qurl.ErrAgentStateContinuity) {
		t.Fatalf("Close after replacement = %v, want ErrAgentStateContinuity", err)
	}
	if err := owner.Close(); !errors.Is(err, qurl.ErrAgentStateContinuity) {
		t.Fatalf("second Close = %v, want stable first close error", err)
	}
}

func TestSDKStoreRefreshMarkerRoundTripsThroughRetainedStateDir(t *testing.T) {
	dir := filepath.Join(realSDKTempDir(t), "state")
	t.Setenv(EnvKeyProvider, KeyProviderFile)
	owner, _ := openSDKStoreForTest(t, dir, "")

	if marker, present, err := owner.LoadRegistrationRefreshMarker(); err != nil || present || marker != (RefreshMarker{}) {
		t.Fatalf("initial marker = (%#v, %v, %v), want absent", marker, present, err)
	}

	// The managed runtime arms the episode through the package-level
	// helper against the same state dir the store owns; the warm-open side
	// must observe it through the store.
	const reason = "sustained native NHP knock failures"
	if err := RequestRegistrationRefresh(dir, reason); err != nil {
		t.Fatal(err)
	}
	marker, present, err := owner.LoadRegistrationRefreshMarker()
	if err != nil || !present {
		t.Fatalf("armed marker = present=%v err=%v, want present", present, err)
	}
	if marker.AttemptCount != 0 || marker.Reason != reason || marker.StartedAtUnix <= 0 {
		t.Fatalf("armed marker = %#v, want fresh recovery episode with reason %q", marker, reason)
	}
	if err := owner.MarkRegistrationRefreshAttempted(); err != nil {
		t.Fatal(err)
	}
	if err := owner.MarkRegistrationRefreshSucceeded(); err != nil {
		t.Fatal(err)
	}
	marker, present, err = owner.LoadRegistrationRefreshMarker()
	if err != nil || !present || marker.RefreshSucceededUnixMilli == 0 || marker.NextAttemptUnixMilli <= marker.LastAttemptUnixMilli {
		t.Fatalf("successful marker handoff = (%#v, %v, %v)", marker, present, err)
	}

	if err := owner.ClearRegistrationRefreshMarker(); err != nil {
		t.Fatal(err)
	}
	if marker, present, err := owner.LoadRegistrationRefreshMarker(); err != nil || present || marker != (RefreshMarker{}) {
		t.Fatalf("cleared marker = (%#v, %v, %v), want absent", marker, present, err)
	}
	if _, err := os.Lstat(filepath.Join(dir, RefreshMarkerFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("marker file after clear: %v, want removed", err)
	}
	if _, present, err := LoadRegistrationRefreshMarker(dir); err != nil || present {
		t.Fatalf("package-level reload = present=%v err=%v, want absent", present, err)
	}
	// Clearing an already-ended episode must stay a success.
	if err := owner.ClearRegistrationRefreshMarker(); err != nil {
		t.Fatalf("idempotent clear = %v, want nil", err)
	}
}

func TestSDKStoreLoadRegistrationRefreshMarkerPropagatesCorruptMarker(t *testing.T) {
	dir := filepath.Join(realSDKTempDir(t), "state")
	t.Setenv(EnvKeyProvider, KeyProviderFile)
	owner, _ := openSDKStoreForTest(t, dir, "")

	markerPath := filepath.Join(dir, RefreshMarkerFile)
	if err := os.WriteFile(markerPath, []byte("{corrupt"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(markerPath, 0o644); err != nil {
		t.Fatal(err)
	}
	marker, present, err := owner.LoadRegistrationRefreshMarker()
	if !errors.Is(err, ErrInvalidRefreshMarker) || present || marker != (RefreshMarker{}) {
		t.Fatalf("corrupt-marker load = (%#v, %v, %v), want ErrInvalidRefreshMarker", marker, present, err)
	}
	// The store's Load must surface corruption without deleting evidence;
	// cleanup is the caller's fail-safe decision.
	if _, statErr := os.Lstat(markerPath); statErr != nil {
		t.Fatalf("corrupt marker file after load: %v, want retained", statErr)
	}
	if err := owner.ClearRegistrationRefreshMarker(); err != nil {
		t.Fatal(err)
	}
	if _, statErr := os.Lstat(markerPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("corrupt marker file after clear: %v, want removed", statErr)
	}
}

func TestSDKStoreRefreshMarkerNeverFollowsReplacementNamespace(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows prevents replacement while the retained directory handle is open")
	}
	parent := realSDKTempDir(t)
	dir := filepath.Join(parent, "state")
	t.Setenv(EnvKeyProvider, KeyProviderFile)
	owner, err := NewSDKStore(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.RequestRegistrationRefresh("test"); err != nil {
		t.Fatal(err)
	}

	displaced := filepath.Join(parent, "state-displaced")
	if err := os.Rename(dir, displaced); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := owner.MarkRegistrationRefreshAttempted(); !errors.Is(err, qurl.ErrAgentStateContinuity) {
		t.Fatalf("MarkRegistrationRefreshAttempted after replacement = %v, want ErrAgentStateContinuity", err)
	}
	raw, err := os.ReadFile(filepath.Join(displaced, RefreshMarkerFile))
	if err != nil {
		t.Fatal(err)
	}
	var marker RefreshMarker
	if err := json.Unmarshal(raw, &marker); err != nil {
		t.Fatal(err)
	}
	if marker.AttemptCount != 0 {
		t.Fatal("displaced refresh marker was mutated after namespace replacement")
	}
	if _, err := os.Lstat(filepath.Join(dir, RefreshMarkerFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement namespace marker exists or stat failed: %v", err)
	}
	if err := owner.Close(); !errors.Is(err, qurl.ErrAgentStateContinuity) {
		t.Fatalf("Close after replacement = %v, want ErrAgentStateContinuity", err)
	}
}

func TestSDKStoreCloseWaitsForInFlightSealedSaveAndRejectsLaterHandoff(t *testing.T) {
	provider := &blockingStateKeyProvider{
		testStateKeyProvider: testStateKeyProvider{name: KeyProviderAWSKMS},
		entered:              make(chan struct{}),
		release:              make(chan struct{}),
	}
	originalFactory := keyProviderForName
	keyProviderForName = func(string) (KeyProvider, error) { return provider, nil }
	t.Cleanup(func() { keyProviderForName = originalFactory })
	t.Setenv(EnvKeyProvider, KeyProviderAWSKMS)

	owner, err := NewSDKStore(filepath.Join(realSDKTempDir(t), "state"), "agent-a")
	if err != nil {
		t.Fatal(err)
	}
	store, err := owner.Handoff()
	if err != nil {
		t.Fatal(err)
	}
	saveDone := make(chan error, 1)
	go func() {
		saveDone <- store.SaveAgentState(context.Background(), &qurl.AgentState{AgentID: "agent-a"})
	}()
	<-provider.entered
	closeDone := make(chan error, 1)
	go func() { closeDone <- owner.Close() }()
	select {
	case err := <-closeDone:
		t.Fatalf("Close returned before in-flight WrapKey completed: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(provider.release)
	if err := <-saveDone; err != nil {
		t.Fatalf("SaveAgentState: %v", err)
	}
	if err := <-closeDone; err != nil {
		t.Fatalf("Close: %v", err)
	}
	if state, err := owner.Handoff(); state != nil || !errors.Is(err, qurl.ErrAgentStateContinuity) {
		t.Fatalf("Handoff after Close = (%T, %v), want nil and ErrAgentStateContinuity", state, err)
	}
}

func TestSDKStoreCloseDetectsNamespaceReplacementWhileSDKCloseBlocks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows prevents replacement while the retained directory handle is open")
	}
	parent := realSDKTempDir(t)
	dir := filepath.Join(parent, "state")
	namespace, err := pinnedfs.EnsurePrivate(dir, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	store := &blockingContinuityStore{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	owner := &SDKStore{
		state:      store,
		continuity: store,
		namespace:  namespace,
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- owner.Close() }()
	<-store.entered

	displaced := filepath.Join(parent, "state-displaced")
	if err := os.Rename(dir, displaced); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	close(store.release)

	if err := <-closeDone; !errors.Is(err, qurl.ErrAgentStateContinuity) ||
		!strings.Contains(err.Error(), "after SDK close") {
		t.Fatalf("Close after replacement during SDK drain = %v, want post-close ErrAgentStateContinuity", err)
	}
	if err := owner.Close(); !errors.Is(err, qurl.ErrAgentStateContinuity) {
		t.Fatalf("second Close = %v, want stable continuity error", err)
	}
}

func TestNewSDKStoreStopsBeforeProviderConstructionWhenStateDirIsNotDurable(t *testing.T) {
	wantErr := errors.New("injected state-directory publication failure")
	originalPrepare := prepareNativeStateDir
	originalFactory := keyProviderForName
	t.Cleanup(func() {
		prepareNativeStateDir = originalPrepare
		keyProviderForName = originalFactory
	})

	prepareNativeStateDir = func(string) (*pinnedfs.Directory, error) {
		return nil, wantErr
	}
	providerConstructed := false
	keyProviderForName = func(string) (KeyProvider, error) {
		providerConstructed = true
		return nil, errors.New("provider must not be constructed")
	}
	t.Setenv(EnvKeyProvider, KeyProviderAWSKMS)

	store, err := NewSDKStore(filepath.Join(t.TempDir(), "state"), "")
	if store != nil {
		t.Fatalf("NewSDKStore returned store %T after state-directory publication failure", store)
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("NewSDKStore error = %v, want %v", err, wantErr)
	}
	if providerConstructed {
		t.Fatal("key provider was constructed before state-directory durability was established")
	}
}

func TestNewSDKStorePinsSDKFilePermissionAndSymlinkRejection(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file modes and symlinks are the contract under test")
	}
	t.Setenv(EnvKeyProvider, KeyProviderFile)

	t.Run("world-readable envelope", func(t *testing.T) {
		dir := filepath.Join(realSDKTempDir(t), "state")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		statePath := filepath.Join(dir, AgentStateFile)
		if err := os.WriteFile(statePath, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(statePath, 0o644); err != nil {
			t.Fatal(err)
		}
		if owner, err := NewSDKStore(dir, ""); owner != nil || !errors.Is(err, qurl.ErrInsecureAgentStatePermissions) {
			t.Fatalf("NewSDKStore = (%T, %v), want nil and ErrInsecureAgentStatePermissions", owner, err)
		}
	})

	t.Run("symlink envelope", func(t *testing.T) {
		dir := filepath.Join(realSDKTempDir(t), "state")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(t.TempDir(), "target.json")
		if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(dir, AgentStateFile)); err != nil {
			t.Fatal(err)
		}
		if owner, err := NewSDKStore(dir, ""); owner != nil || !errors.Is(err, qurl.ErrInvalidAgentState) {
			t.Fatalf("NewSDKStore = (%T, %v), want nil and ErrInvalidAgentState", owner, err)
		}
	})
}

func TestNewSDKStoreSealedProviderRoundTrip(t *testing.T) {
	provider := &testStateKeyProvider{name: KeyProviderAWSKMS}
	originalFactory := keyProviderForName
	keyProviderForName = func(name string) (KeyProvider, error) {
		if name != KeyProviderAWSKMS {
			return nil, fmt.Errorf("unexpected provider %q", name)
		}
		return provider, nil
	}
	t.Cleanup(func() { keyProviderForName = originalFactory })
	t.Setenv(EnvKeyProvider, KeyProviderAWSKMS)

	dir := filepath.Join(realSDKTempDir(t), "state")
	_, store := openSDKStoreForTest(t, dir, "agent-a")
	state := &qurl.AgentState{AgentID: "agent-a", PrivateKeyB64: "private", PublicKeyB64: "public", DeviceAPIKey: "device-secret"}
	if err := store.SaveAgentState(context.Background(), state); err != nil {
		t.Fatalf("SaveAgentState: %v", err)
	}
	loaded, err := store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatalf("LoadAgentState: %v", err)
	}
	if !reflect.DeepEqual(loaded, state) {
		t.Fatalf("sealed state round trip = %#v, want %#v", loaded, state)
	}
	if !provider.unsealSeen || provider.sealCtx["agent_id"] != "agent-a" {
		t.Fatalf("provider binding = %#v, unsealSeen=%v", provider.sealCtx, provider.unsealSeen)
	}
}

func TestNewSDKStoreSealedProviderRejectsConfiguredAgentIDMismatchBeforeUnseal(t *testing.T) {
	provider := &testStateKeyProvider{name: KeyProviderAWSKMS}
	originalFactory := keyProviderForName
	keyProviderForName = func(name string) (KeyProvider, error) {
		if name != KeyProviderAWSKMS {
			return nil, fmt.Errorf("unexpected provider %q", name)
		}
		return provider, nil
	}
	t.Cleanup(func() { keyProviderForName = originalFactory })
	t.Setenv(EnvKeyProvider, KeyProviderAWSKMS)

	dir := filepath.Join(realSDKTempDir(t), "state")
	_, matchingStore := openSDKStoreForTest(t, dir, "agent-a")
	if err := matchingStore.SaveAgentState(context.Background(), &qurl.AgentState{AgentID: "agent-a"}); err != nil {
		t.Fatalf("SaveAgentState: %v", err)
	}

	provider.unsealSeen = false
	_, mismatchedStore := openSDKStoreForTest(t, dir, "agent-b")
	if _, err := mismatchedStore.LoadAgentState(context.Background()); !errors.Is(err, qurl.ErrInvalidAgentState) {
		t.Fatalf("LoadAgentState error = %v, want ErrInvalidAgentState", err)
	}
	if provider.unsealSeen {
		t.Fatal("provider was invoked before configured agent ID mismatch was rejected")
	}
}

func TestNewSDKStoreEnforcesSingleEnvelopeProviderBinding(t *testing.T) {
	tests := []struct {
		name       string
		provider   string
		files      []string
		wantErr    string
		wantSealed bool
	}{
		{name: "empty file provider", provider: KeyProviderFile},
		{name: "file only with file provider", provider: KeyProviderFile, files: []string{AgentStateFile}},
		{name: "empty sealed provider", provider: KeyProviderAWSKMS, wantSealed: true},
		{name: "sealed only with sealed provider", provider: KeyProviderAWSKMS, files: []string{SealedAgentStateFile}, wantSealed: true},
		{name: "both with file provider", provider: KeyProviderFile, files: []string{AgentStateFile, SealedAgentStateFile}, wantErr: "contains both"},
		{name: "both with sealed provider", provider: KeyProviderAWSKMS, files: []string{AgentStateFile, SealedAgentStateFile}, wantErr: "contains both"},
		{name: "sealed state with file provider", provider: KeyProviderFile, files: []string{SealedAgentStateFile}, wantErr: "provider changes are not an in-place migration"},
		{name: "file state with sealed provider", provider: KeyProviderAWSKMS, files: []string{AgentStateFile}, wantErr: "provider changes are not an in-place migration"},
		{name: "legacy split state rejected", provider: KeyProviderFile, files: []string{PrivateKeyFile}, wantErr: "legacy pre-native agent state"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := realSDKTempDir(t)
			if err := os.Chmod(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			for _, name := range tt.files {
				if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv(EnvKeyProvider, tt.provider)
			t.Setenv(EnvAWSKMSKeyID, "arn:aws:kms:us-east-1:111122223333:key/test")
			owner, err := NewSDKStore(dir, "agent-test")
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("NewSDKStore error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := owner.Close(); err != nil {
					t.Errorf("close SDK store: %v", err)
				}
			})
			store, err := owner.Handoff()
			if err != nil {
				t.Fatal(err)
			}
			_, sealed := store.(*qurl.SealedFileAgentStateStore)
			if sealed != tt.wantSealed {
				t.Fatalf("store type = %T, want sealed=%v", store, tt.wantSealed)
			}
		})
	}
}
