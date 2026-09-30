package agentstate

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	qurl "github.com/layervai/qurl-go/qurl"
)

// TestMain pins the fresh-namespace default to the plaintext file so no test
// touches the host's TPM. Tests that exercise the default replace it again.
func TestMain(m *testing.M) {
	defaultFreshKeyProvider = func() string { return KeyProviderFile }
	os.Exit(m.Run())
}

func setFreshKeyProviderForTest(t *testing.T, name string) {
	t.Helper()
	original := defaultFreshKeyProvider
	defaultFreshKeyProvider = func() string { return name }
	t.Cleanup(func() { defaultFreshKeyProvider = original })
}

func TestResolveKeyProviderSelectsByEnvironmentThenEnvelopeThenDefault(t *testing.T) {
	tests := []struct {
		name         string
		env          string
		freshDefault string
		files        map[string]string
		want         string
		wantErr      string
	}{
		{name: "fresh namespace takes a usable TPM", freshDefault: KeyProviderTPM, want: KeyProviderTPM},
		{name: "fresh namespace without a TPM stays plaintext", freshDefault: KeyProviderFile, want: KeyProviderFile},
		{name: "explicit file opts out of the TPM", env: KeyProviderFile, freshDefault: KeyProviderTPM, want: KeyProviderFile},
		{name: "explicit tpm on a fresh namespace", env: KeyProviderTPM, freshDefault: KeyProviderFile, want: KeyProviderTPM},
		{name: "existing plaintext never migrates", freshDefault: KeyProviderTPM, files: map[string]string{AgentStateFile: `{}`}, want: KeyProviderFile},
		{name: "tpm envelope opens without the environment", freshDefault: KeyProviderFile, files: map[string]string{SealedAgentStateFile: `{"provider_id":"tpm"}`}, want: KeyProviderTPM},
		{name: "tpm envelope with explicit tpm", env: "TPM", files: map[string]string{SealedAgentStateFile: `{"provider_id":"tpm"}`}, want: KeyProviderTPM},
		{name: "local-key envelope still needs its environment", files: map[string]string{SealedAgentStateFile: `{"provider_id":"local-key"}`}, wantErr: "set LAYERV_KEY_PROVIDER=local-key"},
		{name: "sealed envelope claiming the file provider is corrupt", freshDefault: KeyProviderTPM, files: map[string]string{SealedAgentStateFile: `{"provider_id":"file"}`}, wantErr: "never seals state"},
		{name: "sealed envelope without a provider id", files: map[string]string{SealedAgentStateFile: `{}`}, wantErr: "does not name its key provider"},
		{name: "explicit tpm over plaintext is not a migration", env: KeyProviderTPM, files: map[string]string{AgentStateFile: `{}`}, wantErr: "provider changes are not an in-place migration"},
		{name: "explicit file over a tpm envelope is not a migration", env: KeyProviderFile, files: map[string]string{SealedAgentStateFile: `{"provider_id":"tpm"}`}, wantErr: "provider changes are not an in-place migration"},
		{name: "unknown provider names tpm among the choices", env: "hsm", wantErr: "local-key, tpm; got \"hsm\""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setFreshKeyProviderForTest(t, tt.freshDefault)
			t.Setenv(EnvKeyProvider, tt.env)
			dir := secureSDKStateDir(t)
			for name, raw := range tt.files {
				writePinnedSDKTestFile(t, dir, name, []byte(raw), 0o600)
			}
			got, err := ResolveKeyProvider(dir)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("ResolveKeyProvider error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveKeyProvider: %v", err)
			}
			if got != tt.want {
				t.Fatalf("ResolveKeyProvider = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveKeyProviderMissingDirectoryResolvesLikeEmptyWithoutCreatingIt(t *testing.T) {
	setFreshKeyProviderForTest(t, KeyProviderTPM)
	t.Setenv(EnvKeyProvider, "")
	dir := filepath.Join(realSDKTempDir(t), "missing")
	got, err := ResolveKeyProvider(dir)
	if err != nil || got != KeyProviderTPM {
		t.Fatalf("ResolveKeyProvider = %q, %v; want tpm", got, err)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatalf("ResolveKeyProvider created %s: %v", dir, err)
	}
}

func TestNewSDKStoreFreshNamespaceSealsWithDefaultProvider(t *testing.T) {
	setFreshKeyProviderForTest(t, KeyProviderTPM)
	t.Setenv(EnvKeyProvider, "")
	provider := &testStateKeyProvider{name: KeyProviderTPM}
	originalFactory := keyProviderForName
	keyProviderForName = func(name string) (KeyProvider, error) {
		if name != KeyProviderTPM {
			t.Fatalf("unexpected provider %q", name)
		}
		return provider, nil
	}
	t.Cleanup(func() { keyProviderForName = originalFactory })

	dir := filepath.Join(realSDKTempDir(t), "state")
	_, store := openSDKStoreForTest(t, dir, "")
	if _, sealed := store.(*qurl.SealedFileAgentStateStore); !sealed {
		t.Fatalf("fresh namespace store = %T, want sealed", store)
	}
	if err := store.SaveAgentState(context.Background(), &qurl.AgentState{AgentID: "agent-a", DeviceAPIKey: "device-secret"}); err != nil {
		t.Fatalf("SaveAgentState: %v", err)
	}

	// A later process whose fresh default is plaintext, and whose environment
	// names nothing, must still reopen the TPM envelope rather than fork a
	// plaintext one beside it.
	setFreshKeyProviderForTest(t, KeyProviderFile)
	_, reopened := openSDKStoreForTest(t, dir, "")
	loaded, err := reopened.LoadAgentState(context.Background())
	if err != nil {
		t.Fatalf("LoadAgentState: %v", err)
	}
	if loaded.DeviceAPIKey != "device-secret" || !provider.unsealSeen {
		t.Fatalf("reopened state = %#v, unsealSeen=%v", loaded, provider.unsealSeen)
	}
	if _, err := os.Lstat(filepath.Join(dir, AgentStateFile)); !os.IsNotExist(err) {
		t.Fatalf("plaintext envelope written beside the sealed one: %v", err)
	}
}

func TestKeyProviderRequiresEnvironment(t *testing.T) {
	for name, want := range map[string]bool{
		KeyProviderFile:     false,
		KeyProviderTPM:      false,
		KeyProviderLocalKey: true,
		KeyProviderAWSKMS:   true,
		KeyProviderGCPKMS:   true,
		"unknown":           true,
	} {
		if got := KeyProviderRequiresEnvironment(name); got != want {
			t.Errorf("KeyProviderRequiresEnvironment(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestTPMRecordRoundTripAndRejectsMalformedRecords(t *testing.T) {
	record := tpmRecord{
		parent:     tpmParentTransientECCSRK,
		parentName: []byte("name"),
		public:     []byte("public"),
		private:    []byte("private"),
		sealed:     []byte("nonce-and-ciphertext"),
	}
	raw, err := record.marshal()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseTPMRecord(raw)
	if err != nil {
		t.Fatalf("parseTPMRecord: %v", err)
	}
	if parsed.parent != record.parent || !bytes.Equal(parsed.parentName, record.parentName) ||
		!bytes.Equal(parsed.public, record.public) || !bytes.Equal(parsed.private, record.private) ||
		!bytes.Equal(parsed.sealed, record.sealed) {
		t.Fatalf("parsed record = %#v, want %#v", parsed, record)
	}

	for name, bad := range map[string][]byte{
		"empty":             nil,
		"unknown parent":    append([]byte{9}, raw[1:]...),
		"truncated length":  raw[:2],
		"truncated field":   raw[:6],
		"missing sealed":    raw[:len(raw)-len(record.sealed)],
		"zero-length field": {byte(tpmParentTransientECCSRK), 0, 0},
	} {
		if _, err := parseTPMRecord(bad); err == nil {
			t.Errorf("%s: parseTPMRecord accepted %x", name, bad)
		}
	}
	if _, err := (tpmRecord{parent: tpmParentTransientECCSRK}).marshal(); err == nil {
		t.Error("marshal accepted empty TPM fields")
	}
}

func TestTPMProviderRejectsForeignRecordsBeforeOpeningTheTPM(t *testing.T) {
	original := openTPM
	t.Cleanup(func() { openTPM = original })
	opened := false
	openTPM = func() (tpmCloser, error) {
		opened = true
		return nil, ErrTPMUnavailable
	}
	provider := tpmKeyProvider{}
	for name, sealed := range map[string]SealedPrivateKey{
		"other provider":   {Provider: KeyProviderLocalKey, KeyID: tpmRecordKeyID, CiphertextBase64: "AA=="},
		"unknown key id":   {Provider: KeyProviderTPM, KeyID: "tpm:v2", CiphertextBase64: "AA=="},
		"malformed record": {Provider: KeyProviderTPM, KeyID: tpmRecordKeyID, CiphertextBase64: "AA=="},
	} {
		if _, err := provider.Unseal(context.Background(), sealed); err == nil {
			t.Errorf("%s: Unseal succeeded", name)
		}
	}
	if opened {
		t.Fatal("Unseal opened the TPM for a record it should have rejected first")
	}
}

func TestProbeTPMCachesItsFirstResult(t *testing.T) {
	original := openTPM
	t.Cleanup(func() {
		openTPM = original
		tpmProbe.Lock()
		tpmProbe.done, tpmProbe.err = false, nil
		tpmProbe.Unlock()
	})
	tpmProbe.Lock()
	tpmProbe.done, tpmProbe.err = false, nil
	tpmProbe.Unlock()
	calls := 0
	openTPM = func() (tpmCloser, error) {
		calls++
		return nil, os.ErrPermission
	}
	for range 3 {
		if err := ProbeTPM(); !errors.Is(err, ErrTPMUnavailable) {
			t.Fatalf("ProbeTPM = %v, want ErrTPMUnavailable", err)
		}
	}
	if calls != 1 {
		t.Fatalf("ProbeTPM opened the TPM %d times, want 1", calls)
	}
}

// TestResolveKeyProviderFollowsSymlinkedAncestors pins that resolution does not
// impose the Connector namespace's ancestor rules: embedders open the plaintext
// envelope with qurl-go's own capability, which accepts a state directory
// reached through a symlinked home or temporary directory.
func TestResolveKeyProviderFollowsSymlinkedAncestors(t *testing.T) {
	setFreshKeyProviderForTest(t, KeyProviderFile)
	t.Setenv(EnvKeyProvider, "")
	real := secureSDKStateDir(t)
	writePinnedSDKTestFile(t, real, SealedAgentStateFile, []byte(`{"provider_id":"tpm"}`), 0o600)
	link := filepath.Join(realSDKTempDir(t), "linked")
	if err := os.Symlink(filepath.Dir(real), link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	got, err := ResolveKeyProvider(filepath.Join(link, filepath.Base(real)))
	if err != nil || got != KeyProviderTPM {
		t.Fatalf("ResolveKeyProvider through a symlinked ancestor = %q, %v; want tpm", got, err)
	}
}

// blockingTPM stands in for a wedged TPM: opening it blocks until release.
func blockingTPM(t *testing.T) {
	t.Helper()
	release := make(chan struct{})
	original := openTPM
	openTPM = func() (tpmCloser, error) {
		<-release
		return nil, ErrTPMUnavailable
	}
	t.Cleanup(func() {
		close(release)
		openTPM = original
	})
}

func TestTPMProviderSealHonorsTheCallerDeadline(t *testing.T) {
	blockingTPM(t)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := tpmKeyProvider{}.Seal(ctx, make([]byte, StateDEKSize), map[string]string{"agent_id": "a"})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Seal against a wedged TPM = %v, want DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Seal returned after %s, want promptly after the deadline", elapsed)
	}
}
