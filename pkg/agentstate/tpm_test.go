package agentstate

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	qurl "github.com/layervai/qurl-go/qurl"
)

// TestMain pins the fresh-namespace default to the plaintext file so no test
// touches the host's TPM. Tests that exercise the default replace it again.
var originalDefaultFreshKeyProvider = defaultFreshKeyProvider

func TestMain(m *testing.M) {
	defaultFreshKeyProvider = func() (string, error) { return KeyProviderFile, nil }
	os.Exit(m.Run())
}

func setFreshKeyProviderForTest(t *testing.T, name string) {
	t.Helper()
	original := defaultFreshKeyProvider
	defaultFreshKeyProvider = func() (string, error) { return name, nil }
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
		// Abandoned operations drain asynchronously; later tests must not
		// start against a TPM this one left looking wedged.
		deadline := time.Now().Add(5 * time.Second)
		for {
			tpmAbandoned.Lock()
			n := tpmAbandoned.count
			tpmAbandoned.Unlock()
			if n == 0 {
				return
			}
			if time.Now().After(deadline) {
				t.Errorf("%d abandoned TPM operations never finished", n)
				return
			}
			time.Sleep(time.Millisecond)
		}
	})
}

func resetTPMProbeForTest(t *testing.T) {
	t.Helper()
	reset := func() {
		tpmProbe.Lock()
		tpmProbe.done, tpmProbe.err = false, nil
		tpmProbe.Unlock()
	}
	reset()
	t.Cleanup(reset)
}

func TestTPMProviderFailsFastWhileAnEarlierOperationIsWedged(t *testing.T) {
	blockingTPM(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := (tpmKeyProvider{}).Seal(ctx, make([]byte, StateDEKSize), nil); !errors.Is(err, ErrTPMNotResponding) {
		t.Fatalf("first Seal = %v, want ErrTPMNotResponding", err)
	}
	start := time.Now()
	_, err := tpmKeyProvider{}.Seal(context.Background(), make([]byte, StateDEKSize), nil)
	if !errors.Is(err, ErrTPMNotResponding) || !strings.Contains(err.Error(), "has not returned") {
		t.Fatalf("second Seal = %v, want an immediate not-responding refusal", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("second Seal waited %s behind a wedged TPM", elapsed)
	}
}

func TestProbeTPMIsBoundedAndDoesNotCacheATransientFailure(t *testing.T) {
	resetTPMProbeForTest(t)
	originalTimeout := tpmProbeTimeout
	tpmProbeTimeout = 20 * time.Millisecond
	t.Cleanup(func() { tpmProbeTimeout = originalTimeout })
	blockingTPM(t)
	if err := ProbeTPM(); !errors.Is(err, ErrTPMNotResponding) {
		t.Fatalf("ProbeTPM against a wedged TPM = %v, want ErrTPMNotResponding", err)
	}
	tpmProbe.Lock()
	cached := tpmProbe.done
	tpmProbe.Unlock()
	if cached {
		t.Fatal("ProbeTPM cached a transient failure")
	}
}

func TestProbeTPMRetriesABusyDeviceAndCachesAMissingOne(t *testing.T) {
	resetTPMProbeForTest(t)
	original := openTPM
	t.Cleanup(func() { openTPM = original })
	calls := 0
	openErr := error(syscall.EBUSY)
	openTPM = func() (tpmCloser, error) {
		calls++
		return nil, &os.PathError{Op: "open", Path: "/dev/tpmrm0", Err: openErr}
	}
	for range 2 {
		if err := ProbeTPM(); !errors.Is(err, ErrTPMNotResponding) {
			t.Fatalf("ProbeTPM on a busy device = %v, want ErrTPMNotResponding", err)
		}
	}
	openErr = syscall.ENOENT
	for range 2 {
		if err := ProbeTPM(); !errors.Is(err, ErrTPMUnavailable) {
			t.Fatalf("ProbeTPM on a missing device = %v, want ErrTPMUnavailable", err)
		}
	}
	if calls != 3 {
		t.Fatalf("ProbeTPM opened the device %d times, want 3 (two busy retries, one cached miss)", calls)
	}
}

func TestFreshNamespaceRefusesPlaintextWhileTheTPMIsNotResponding(t *testing.T) {
	resetTPMProbeForTest(t)
	t.Setenv(EnvKeyProvider, "")
	original := defaultFreshKeyProvider
	defaultFreshKeyProvider = originalDefaultFreshKeyProvider
	t.Cleanup(func() { defaultFreshKeyProvider = original })
	originalOpen := openTPM
	t.Cleanup(func() { openTPM = originalOpen })
	openTPM = func() (tpmCloser, error) { return nil, syscall.EBUSY }
	_, err := ResolveKeyProvider(secureSDKStateDir(t))
	if !errors.Is(err, ErrTPMNotResponding) || !strings.Contains(err.Error(), EnvKeyProvider+"="+KeyProviderFile) {
		t.Fatalf("ResolveKeyProvider with a busy TPM = %v, want a not-responding error naming the opt-out", err)
	}
	openTPM = func() (tpmCloser, error) { return nil, os.ErrPermission }
	if got, err := ResolveKeyProvider(secureSDKStateDir(t)); err != nil || got != KeyProviderFile {
		t.Fatalf("ResolveKeyProvider without TPM permission = %q, %v; want the plaintext fallback", got, err)
	}
}

func TestClassifyTPMErrorSeparatesStructuralFromTransient(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want error
	}{
		"auth failure":       {err: tpm2.TPMRCBadAuth, want: ErrTPMUnavailable},
		"handle not found":   {err: tpm2.TPMFmt1Error{}, want: ErrTPMUnavailable},
		"retry warning":      {err: tpm2.TPMRCRetry, want: ErrTPMNotResponding},
		"testing warning":    {err: tpm2.TPMRCTesting, want: ErrTPMNotResponding},
		"device i/o":         {err: io.ErrUnexpectedEOF, want: ErrTPMNotResponding},
		"deadline":           {err: context.DeadlineExceeded, want: ErrTPMNotResponding},
		"already classified": {err: ErrTPMUnavailable, want: ErrTPMUnavailable},
	} {
		if got := classifyTPMError(tc.err); !errors.Is(got, tc.want) {
			t.Errorf("%s: classifyTPMError(%v) = %v, want %v", name, tc.err, got, tc.want)
		}
	}
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

func resetTPMParentMemo(t *testing.T) {
	t.Helper()
	reset := func() {
		tpmParentMemo.Lock()
		tpmParentMemo.kind = 0
		tpmParentMemo.Unlock()
	}
	reset()
	t.Cleanup(reset)
}

// TestTPMECCSRKTemplateIsPinned pins the exact template bytes every persisted
// record's parent Name derives from. If this fails, the change orphans every
// existing TPM-sealed namespace unless it ships as a new tpmParent kind.
func TestTPMECCSRKTemplateIsPinned(t *testing.T) {
	const want = "0023000b0003047200000006008000430010000300100020000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000"
	got := hex.EncodeToString(tpm2.Marshal(tpmECCSRKTemplate()))
	if got != want {
		t.Fatalf("ECC SRK template bytes changed:\n got %s\nwant %s", got, want)
	}
}

func TestTPMWedgeGateReopensAfterItsBackoff(t *testing.T) {
	blockingTPM(t)
	originalBackoff := tpmWedgeBackoff
	tpmWedgeBackoff = 50 * time.Millisecond
	t.Cleanup(func() { tpmWedgeBackoff = originalBackoff })
	short := func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(context.Background(), 10*time.Millisecond)
	}
	ctx, cancel := short()
	defer cancel()
	if _, err := (tpmKeyProvider{}).Seal(ctx, make([]byte, StateDEKSize), nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("first Seal = %v, want an abandoned deadline", err)
	}
	if _, err := (tpmKeyProvider{}).Seal(context.Background(), make([]byte, StateDEKSize), nil); err == nil || !strings.Contains(err.Error(), "has not returned") {
		t.Fatalf("Seal inside the backoff = %v, want an immediate refusal", err)
	}
	time.Sleep(60 * time.Millisecond)
	ctx2, cancel2 := short()
	defer cancel2()
	if _, err := (tpmKeyProvider{}).Seal(ctx2, make([]byte, StateDEKSize), nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Seal after the backoff = %v, want it let through to the TPM", err)
	}
}

func TestTPMProviderReportsABusyDeviceAsNotResponding(t *testing.T) {
	original := openTPM
	t.Cleanup(func() { openTPM = original })
	openTPM = func() (tpmCloser, error) { return nil, syscall.EBUSY }
	if _, err := (tpmKeyProvider{}).Seal(context.Background(), make([]byte, StateDEKSize), nil); !errors.Is(err, ErrTPMNotResponding) || errors.Is(err, ErrTPMUnavailable) {
		t.Fatalf("Seal with a busy device = %v, want only ErrTPMNotResponding", err)
	}
}

func TestTPMCommandErrorKeepsRecordFailuresUnclassified(t *testing.T) {
	if err := tpmCommandError("load", tpm2.TPMRCIntegrity); errors.Is(err, ErrTPMNotResponding) || errors.Is(err, ErrTPMUnavailable) {
		t.Fatalf("integrity failure classified as %v", err)
	}
	if err := tpmCommandError("load", tpm2.TPMRCRetry); !errors.Is(err, ErrTPMNotResponding) {
		t.Fatalf("retry warning = %v, want ErrTPMNotResponding", err)
	}
}

// TestReadOnlyEntryPointsNeverProbeTheTPM pins that only a caller about to
// create an envelope asks the TPM anything: display and validation paths on
// an empty namespace must neither pay the probe nor fail on its result.
func TestReadOnlyEntryPointsNeverProbeTheTPM(t *testing.T) {
	t.Setenv(EnvKeyProvider, "")
	original := defaultFreshKeyProvider
	probed := 0
	defaultFreshKeyProvider = func() (string, error) {
		probed++
		return "", ErrTPMNotResponding
	}
	t.Cleanup(func() { defaultFreshKeyProvider = original })

	dir := secureSDKStateDir(t)
	if err := ValidateSDKStoreLayoutReadOnly(dir); err != nil {
		t.Fatalf("ValidateSDKStoreLayoutReadOnly: %v", err)
	}
	if err := ValidateSDKStoreLayout(dir); err != nil {
		t.Fatalf("ValidateSDKStoreLayout: %v", err)
	}
	if reader, err := OpenSDKStateReader(dir, ""); err == nil {
		_ = reader.Close()
	} else if errors.Is(err, ErrTPMNotResponding) {
		t.Fatalf("OpenSDKStateReader failed on the probe: %v", err)
	}
	if probed != 0 {
		t.Fatalf("read-only entry points probed the TPM %d times", probed)
	}
	if _, err := NewSDKStore(dir, ""); !errors.Is(err, ErrTPMNotResponding) || probed != 1 {
		t.Fatalf("NewSDKStore = %v after %d probes, want the create path to probe once and refuse", err, probed)
	}
}
