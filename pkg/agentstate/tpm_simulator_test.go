//go:build cgo && !windows

package agentstate

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
	qurl "github.com/layervai/qurl-go/qurl"
)

// sharedSimulator keeps one simulator alive across the provider's own
// open/close cycles: closing the real simulator would discard its owner seed,
// and with it every storage root key the test sealed under.
type sharedSimulator struct{ transport.TPMCloser }

func (sharedSimulator) Close() error { return nil }

func useTPMSimulator(t *testing.T) transport.TPM {
	t.Helper()
	sim, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("open TPM simulator: %v", err)
	}
	original := openTPM
	openTPM = func() (tpmCloser, error) { return sharedSimulator{sim}, nil }
	t.Cleanup(func() {
		openTPM = original
		if err := sim.Close(); err != nil {
			t.Errorf("close TPM simulator: %v", err)
		}
	})
	return sim
}

// requireNoTransientHandles proves every seal, unseal, and probe flushed the
// objects it loaded.
func requireNoTransientHandles(t *testing.T, tpm transport.TPM) {
	t.Helper()
	rsp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapHandles,
		Property:      uint32(tpm2.TPMHTTransient) << 24,
		PropertyCount: 8,
	}.Execute(tpm)
	if err != nil {
		t.Fatalf("list transient handles: %v", err)
	}
	handles, err := rsp.CapabilityData.Data.Handles()
	if err != nil {
		t.Fatalf("decode transient handles: %v", err)
	}
	if len(handles.Handle) != 0 {
		t.Fatalf("TPM holds %d leaked transient handles", len(handles.Handle))
	}
}

func TestTPMProviderSealsToTheSimulator(t *testing.T) {
	sim := useTPMSimulator(t)
	provider := tpmKeyProvider{}
	dek := bytes.Repeat([]byte{0x5a}, StateDEKSize)
	encContext := map[string]string{"agent_id": "agent-a", "purpose": "test"}

	sealed, err := provider.Seal(context.Background(), dek, encContext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	requireNoTransientHandles(t, sim)
	if sealed.Provider != KeyProviderTPM || sealed.KeyID != tpmRecordKeyID {
		t.Fatalf("sealed record = %#v", sealed)
	}
	raw, err := sealedCiphertextBytes(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, dek) {
		t.Fatal("sealed record contains the plaintext DEK")
	}

	got, err := provider.Unseal(context.Background(), sealed)
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	requireNoTransientHandles(t, sim)
	if !bytes.Equal(got, dek) {
		t.Fatalf("Unseal = %x, want %x", got, dek)
	}

	t.Run("deadline", func(t *testing.T) {
		blockingTPM(t)
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		if _, err := provider.Unseal(ctx, sealed); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Unseal against a wedged TPM = %v, want DeadlineExceeded", err)
		}
	})

	t.Run("binding tamper", func(t *testing.T) {
		tampered := sealed
		tampered.EncryptionContext = map[string]string{"agent_id": "agent-b", "purpose": "test"}
		if _, err := provider.Unseal(context.Background(), tampered); err == nil || !strings.Contains(err.Error(), "authentication failed") {
			t.Fatalf("Unseal with another binding = %v, want an authentication failure", err)
		}
		requireNoTransientHandles(t, sim)
	})

	t.Run("foreign storage root", func(t *testing.T) {
		record, err := parseTPMRecord(raw)
		if err != nil {
			t.Fatal(err)
		}
		record.parentName = append([]byte(nil), record.parentName...)
		record.parentName[len(record.parentName)-1] ^= 0xff
		foreign, err := record.marshal()
		if err != nil {
			t.Fatal(err)
		}
		tampered := sealed
		tampered.CiphertextBase64 = base64.StdEncoding.EncodeToString(foreign)
		if _, err := provider.Unseal(context.Background(), tampered); err == nil || !strings.Contains(err.Error(), "TPM was cleared") {
			t.Fatalf("Unseal under another storage root = %v, want the TPM-cleared diagnosis", err)
		}
		requireNoTransientHandles(t, sim)
	})

	t.Run("sealed object tamper", func(t *testing.T) {
		record, err := parseTPMRecord(raw)
		if err != nil {
			t.Fatal(err)
		}
		record.private = append([]byte(nil), record.private...)
		record.private[len(record.private)-1] ^= 0xff
		broken, err := record.marshal()
		if err != nil {
			t.Fatal(err)
		}
		tampered := sealed
		tampered.CiphertextBase64 = base64.StdEncoding.EncodeToString(broken)
		if _, err := provider.Unseal(context.Background(), tampered); err == nil {
			t.Fatal("Unseal accepted a tampered TPM private area")
		}
		requireNoTransientHandles(t, sim)
	})
}

func TestProbeTPMSucceedsOnTheSimulatorWithoutLeakingHandles(t *testing.T) {
	sim := useTPMSimulator(t)
	t.Cleanup(func() {
		tpmProbe.Lock()
		tpmProbe.done, tpmProbe.err = false, nil
		tpmProbe.Unlock()
	})
	tpmProbe.Lock()
	tpmProbe.done, tpmProbe.err = false, nil
	tpmProbe.Unlock()
	if err := ProbeTPM(); err != nil {
		t.Fatalf("ProbeTPM: %v", err)
	}
	requireNoTransientHandles(t, sim)
}

func TestTPMProviderFallsBackToThePersistentSRK(t *testing.T) {
	sim := useTPMSimulator(t)
	created, err := tpm2.CreatePrimary{PrimaryHandle: tpm2.TPMRHOwner, InPublic: tpm2.New2B(tpm2.RSASRKTemplate)}.Execute(sim)
	if err != nil {
		t.Fatalf("create RSA SRK: %v", err)
	}
	if _, err := (tpm2.EvictControl{
		Auth:             tpm2.TPMRHOwner,
		ObjectHandle:     &tpm2.NamedHandle{Handle: created.ObjectHandle, Name: created.Name},
		PersistentHandle: tpmPersistentSRKHandle,
	}).Execute(sim); err != nil {
		t.Fatalf("persist SRK: %v", err)
	}
	if err := flushTPMHandle(sim, created.ObjectHandle); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = tpm2.EvictControl{
			Auth:             tpm2.TPMRHOwner,
			ObjectHandle:     &tpm2.NamedHandle{Handle: tpmPersistentSRKHandle, Name: created.Name},
			PersistentHandle: tpmPersistentSRKHandle,
		}.Execute(sim)
	})
	// Give the owner hierarchy an authorization value, as Windows does, so the
	// transient ECC SRK cannot be created.
	if _, err := (tpm2.HierarchyChangeAuth{
		AuthHandle: tpm2.TPMRHOwner,
		NewAuth:    tpm2.TPM2BAuth{Buffer: []byte("discarded-owner-auth")},
	}).Execute(sim); err != nil {
		t.Fatalf("set owner auth: %v", err)
	}
	t.Cleanup(func() {
		_, _ = tpm2.HierarchyChangeAuth{
			AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth([]byte("discarded-owner-auth"))},
			NewAuth:    tpm2.TPM2BAuth{},
		}.Execute(sim)
	})

	provider := tpmKeyProvider{}
	dek := bytes.Repeat([]byte{0x33}, StateDEKSize)
	sealed, err := provider.Seal(context.Background(), dek, map[string]string{"agent_id": "agent-a"})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	raw, err := sealedCiphertextBytes(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if record, err := parseTPMRecord(raw); err != nil || record.parent != tpmParentPersistentSRK {
		t.Fatalf("record parent = %v, %v; want the persistent SRK", record.parent, err)
	}
	got, err := provider.Unseal(context.Background(), sealed)
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("Unseal = %x, %v", got, err)
	}
	requireNoTransientHandles(t, sim)
}

func TestSDKStoreDefaultsFreshNamespacesToTheTPM(t *testing.T) {
	sim := useTPMSimulator(t)
	t.Setenv(EnvKeyProvider, "")
	original := defaultFreshKeyProvider
	defaultFreshKeyProvider = func() string {
		if ProbeTPM() == nil {
			return KeyProviderTPM
		}
		return KeyProviderFile
	}
	t.Cleanup(func() {
		defaultFreshKeyProvider = original
		tpmProbe.Lock()
		tpmProbe.done, tpmProbe.err = false, nil
		tpmProbe.Unlock()
	})

	dir := filepath.Join(realSDKTempDir(t), "state")
	_, store := openSDKStoreForTest(t, dir, "")
	state := &qurl.AgentState{AgentID: "agent-a", PrivateKeyB64: "private", PublicKeyB64: "public", DeviceAPIKey: "device-secret"}
	if err := store.SaveAgentState(context.Background(), state); err != nil {
		t.Fatalf("SaveAgentState: %v", err)
	}
	if got, err := ResolveKeyProvider(dir); err != nil || got != KeyProviderTPM {
		t.Fatalf("ResolveKeyProvider after save = %q, %v; want tpm", got, err)
	}
	reader, err := OpenSDKStateReader(dir, "")
	if err != nil {
		t.Fatalf("OpenSDKStateReader: %v", err)
	}
	loaded, err := reader.LoadAgentState(context.Background())
	closeErr := reader.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("LoadAgentState = %v, close = %v", err, closeErr)
	}
	if loaded.DeviceAPIKey != state.DeviceAPIKey {
		t.Fatalf("loaded state = %#v", loaded)
	}
	requireNoTransientHandles(t, sim)
}
