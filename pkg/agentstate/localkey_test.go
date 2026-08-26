package agentstate

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	qurl "github.com/layervai/qurl-go/qurl"
)

func testLocalKeyProvider(t *testing.T, fill byte) localKeyProvider {
	t.Helper()
	provider, err := newLocalKeyProvider(bytes.Repeat([]byte{fill}, localWrappingKeySize))
	if err != nil {
		t.Fatalf("newLocalKeyProvider: %v", err)
	}
	return provider
}

func clearLocalKeyProviderCache() {
	localKeyCache.Lock()
	scrubBytes(localKeyCache.key)
	localKeyCache.fd = ""
	localKeyCache.key = nil
	localKeyCache.Unlock()
}

func resetLocalKeyProviderCache(t *testing.T) {
	t.Helper()
	clearLocalKeyProviderCache()
	t.Cleanup(clearLocalKeyProviderCache)
}

func localKeyTestBinding(agentID string) qurl.AgentStateKeyBinding {
	return qurl.AgentStateKeyBinding{
		Purpose:         "native-agent-state",
		EnvelopeVersion: 1,
		ProviderID:      KeyProviderLocalKey,
		AgentID:         agentID,
	}
}

func TestLocalKeyProviderRoundTripAndAuthentication(t *testing.T) {
	provider := testLocalKeyProvider(t, 0x41)
	plaintext := bytes.Repeat([]byte{0x72}, StateDEKSize)
	contextMap := sdkKeyEncryptionContext(localKeyTestBinding("agent-alpha"))

	sealed, err := provider.Seal(context.Background(), plaintext, contextMap)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if sealed.Provider != KeyProviderLocalKey || sealed.KeyID != localKeyRecordKeyID {
		t.Fatalf("sealed identity = %q/%q, want %q/%q", sealed.Provider, sealed.KeyID, KeyProviderLocalKey, localKeyRecordKeyID)
	}
	got, err := provider.Unseal(context.Background(), sealed)
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("unsealed state DEK differs")
	}

	unsupportedKeyID := sealed
	unsupportedKeyID.KeyID = "local-key:v2"
	if _, err := provider.Unseal(context.Background(), unsupportedKeyID); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("Unseal err = %v, want unsupported local key id", err)
	}

	tampered := sealed
	ciphertext, err := base64.StdEncoding.DecodeString(tampered.CiphertextBase64)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[len(ciphertext)-1] ^= 0x01
	tampered.CiphertextBase64 = base64.StdEncoding.EncodeToString(ciphertext)
	if _, err := provider.Unseal(context.Background(), tampered); err == nil {
		t.Fatal("Unseal accepted tampered ciphertext")
	}

	sealed.EncryptionContext["agent_id"] = "agent-beta"
	if _, err := provider.Unseal(context.Background(), sealed); err == nil {
		t.Fatal("Unseal accepted tampered authenticated context")
	}
}

func TestLocalKeyProviderRejectsDifferentOSKeystoreKey(t *testing.T) {
	first := testLocalKeyProvider(t, 0x41)
	second := testLocalKeyProvider(t, 0x42)
	sealed, err := first.Seal(
		context.Background(),
		bytes.Repeat([]byte{0x72}, StateDEKSize),
		sdkKeyEncryptionContext(localKeyTestBinding("agent-alpha")),
	)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := second.Unseal(context.Background(), sealed); err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("Unseal err = %v, want authentication failure", err)
	}
}

func TestLocalKeyProviderNormalizesEmptyContextAcrossJSONRoundTrip(t *testing.T) {
	provider := testLocalKeyProvider(t, 0x41)
	plaintext := bytes.Repeat([]byte{0x72}, StateDEKSize)
	sealed, err := provider.Seal(context.Background(), plaintext, map[string]string{})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	record, err := json.Marshal(sealed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var roundTripped SealedPrivateKey
	if err := json.Unmarshal(record, &roundTripped); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if roundTripped.EncryptionContext != nil {
		t.Fatalf("round-tripped empty encryption context = %#v, want nil", roundTripped.EncryptionContext)
	}
	got, err := provider.Unseal(context.Background(), roundTripped)
	if err != nil {
		t.Fatalf("Unseal after JSON round trip: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("unsealed state DEK differs")
	}
}

func TestLocalKeyProviderDoesNotAliasCallerKey(t *testing.T) {
	key := bytes.Repeat([]byte{0x41}, localWrappingKeySize)
	provider, err := newLocalKeyProvider(key)
	if err != nil {
		t.Fatalf("newLocalKeyProvider: %v", err)
	}
	scrubBytes(key)

	plaintext := bytes.Repeat([]byte{0x72}, StateDEKSize)
	sealed, err := provider.Seal(
		context.Background(),
		plaintext,
		sdkKeyEncryptionContext(localKeyTestBinding("agent-alpha")),
	)
	if err != nil {
		t.Fatalf("Seal after caller scrub: %v", err)
	}
	got, err := provider.Unseal(context.Background(), sealed)
	if err != nil {
		t.Fatalf("Unseal after caller scrub: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("provider key changed when the caller buffer was scrubbed")
	}
}

func TestLocalKeyProviderRequiresAES256Key(t *testing.T) {
	invalidKey := bytes.Repeat([]byte{0x41}, localWrappingKeySize-1)
	if _, err := newLocalKeyProviderOwned(invalidKey); err == nil {
		t.Fatal("newLocalKeyProvider accepted a non-256-bit key")
	}
	if !bytes.Equal(invalidKey, make([]byte, len(invalidKey))) {
		t.Fatal("newLocalKeyProviderOwned did not scrub the rejected caller-owned key")
	}
}
