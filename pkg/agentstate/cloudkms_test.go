package agentstate

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
)

type fixedAWSKMSClient struct {
	decryptOut *awskms.DecryptOutput
}

func (c fixedAWSKMSClient) Encrypt(context.Context, *awskms.EncryptInput, ...func(*awskms.Options)) (*awskms.EncryptOutput, error) {
	return nil, nil
}

func (c fixedAWSKMSClient) Decrypt(context.Context, *awskms.DecryptInput, ...func(*awskms.Options)) (*awskms.DecryptOutput, error) {
	return c.decryptOut, nil
}

func TestGCPKMSCRCValidation(t *testing.T) {
	plaintext := []byte("state DEK")
	aad := []byte(`{"agent_id":"agent-a"}`)
	encryptReq := gcpEncryptRequest("projects/p/locations/l/keyRings/r/cryptoKeys/k", plaintext, aad)
	if !gcpCRC32CMatches(plaintext, encryptReq.PlaintextCrc32C) || !gcpCRC32CMatches(aad, encryptReq.AdditionalAuthenticatedDataCrc32C) {
		t.Fatal("encrypt request did not bind plaintext and AAD CRC32C values")
	}

	ciphertext := []byte("ciphertext")
	encryptOut := &kmspb.EncryptResponse{
		Ciphertext: ciphertext, CiphertextCrc32C: gcpCRC32CValue(ciphertext),
		VerifiedPlaintextCrc32C: true, VerifiedAdditionalAuthenticatedDataCrc32C: true,
	}
	if err := validateGCPEncryptResponse(encryptOut, aad); err != nil {
		t.Fatalf("valid encrypt response: %v", err)
	}
	encryptOut.CiphertextCrc32C = gcpCRC32CValue([]byte("different"))
	if err := validateGCPEncryptResponse(encryptOut, aad); err == nil || !strings.Contains(err.Error(), "ciphertext crc32c mismatch") {
		t.Fatalf("encrypt CRC mismatch error = %v", err)
	}

	decryptReq := gcpDecryptRequest("key", ciphertext, aad)
	if !gcpCRC32CMatches(ciphertext, decryptReq.CiphertextCrc32C) || !gcpCRC32CMatches(aad, decryptReq.AdditionalAuthenticatedDataCrc32C) {
		t.Fatal("decrypt request did not bind ciphertext and AAD CRC32C values")
	}
	decryptOut := &kmspb.DecryptResponse{Plaintext: plaintext, PlaintextCrc32C: gcpCRC32CValue(plaintext)}
	if err := validateGCPDecryptResponse(decryptOut); err != nil {
		t.Fatalf("valid decrypt response: %v", err)
	}
	decryptOut.PlaintextCrc32C = gcpCRC32CValue([]byte("different"))
	if err := validateGCPDecryptResponse(decryptOut); err == nil || !strings.Contains(err.Error(), "plaintext crc32c mismatch") {
		t.Fatalf("decrypt CRC mismatch error = %v", err)
	}
}

func TestReadAWSNitroAttestationDocumentEncodings(t *testing.T) {
	dir := t.TempDir()
	raw := []byte{0x01, 0x02, 0x03, 0x04}
	rawPath := filepath.Join(dir, "raw.cose")
	if err := os.WriteFile(rawPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readAWSNitroAttestationDocument(rawPath, "raw")
	if err != nil || string(got) != string(raw) {
		t.Fatalf("raw document = %x, %v; want %x", got, err, raw)
	}

	base64Path := filepath.Join(dir, "base64.cose")
	if err := os.WriteFile(base64Path, []byte(base64.StdEncoding.EncodeToString(raw)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, encoding := range []string{"base64", "auto"} {
		got, err := readAWSNitroAttestationDocument(base64Path, encoding)
		if err != nil || string(got) != string(raw) {
			t.Fatalf("%s document = %x, %v; want %x", encoding, got, err, raw)
		}
	}

	// This locks the documented ambiguity: explicit raw preserves a valid-
	// base64 byte sequence while auto decodes it.
	ambiguous := []byte("YWJj")
	ambiguousPath := filepath.Join(dir, "ambiguous.cose")
	if err := os.WriteFile(ambiguousPath, ambiguous, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = readAWSNitroAttestationDocument(ambiguousPath, "raw")
	if err != nil || string(got) != string(ambiguous) {
		t.Fatalf("explicit raw ambiguity handling = %q, %v", got, err)
	}
	got, err = readAWSNitroAttestationDocument(ambiguousPath, "auto")
	if err != nil || string(got) != "abc" {
		t.Fatalf("auto ambiguity handling = %q, %v; want abc", got, err)
	}
}

func TestAWSNitroUnsealRejectsHostPlaintextAndInvalidDEK(t *testing.T) {
	originalFactory := newAWSKMSClient
	t.Cleanup(func() { newAWSKMSClient = originalFactory })
	sealed := sealedCiphertextRecord(KeyProviderAWSNitro, "key", []byte("ciphertext"), map[string]string{"agent_id": "agent-a"})
	sealed.Region = "us-east-1"

	hostPlaintext := []byte("must be scrubbed")
	newAWSKMSClient = func(context.Context, string) (awsKMSClient, string, error) {
		return fixedAWSKMSClient{decryptOut: &awskms.DecryptOutput{Plaintext: hostPlaintext}}, "us-east-1", nil
	}
	provider := awsNitroKeyProvider{
		awsKMSKeyProvider:         awsKMSKeyProvider{keyID: "key", region: "us-east-1", providerName: KeyProviderAWSNitro},
		attestationDocument:       []byte("attestation"),
		unwrapRecipientCiphertext: func(context.Context, []byte) ([]byte, error) { return make([]byte, StateDEKSize), nil },
	}
	if _, err := provider.Unseal(context.Background(), sealed); err == nil || !strings.Contains(err.Error(), "host plaintext") {
		t.Fatalf("host plaintext error = %v", err)
	}
	for i, b := range hostPlaintext {
		if b != 0 {
			t.Fatalf("host plaintext byte %d was not scrubbed", i)
		}
	}

	newAWSKMSClient = func(context.Context, string) (awsKMSClient, string, error) {
		return fixedAWSKMSClient{decryptOut: &awskms.DecryptOutput{CiphertextForRecipient: []byte("recipient ciphertext")}}, "us-east-1", nil
	}
	badDEK := make([]byte, StateDEKSize-1)
	provider.unwrapRecipientCiphertext = func(context.Context, []byte) ([]byte, error) { return badDEK, nil }
	if _, err := provider.Unseal(context.Background(), sealed); err == nil || !strings.Contains(err.Error(), "state DEK size") {
		t.Fatalf("invalid DEK size error = %v", err)
	}
	for i, b := range badDEK {
		if b != 0 {
			t.Fatalf("invalid DEK byte %d was not scrubbed", i)
		}
	}
}

func TestGCPConfidentialSpaceAttestationClaims(t *testing.T) {
	const (
		imageDigest    = "sha256:0123456789abcdef"
		serviceAccount = "connector@example.iam.gserviceaccount.com"
	)
	validClaims := map[string]any{
		"exp": time.Now().Add(time.Hour).Unix(), "swname": "CONFIDENTIAL_SPACE", "dbgstat": "disabled-since-boot",
		"google_service_accounts": []string{serviceAccount},
		"submods": map[string]any{
			"confidential_space": map[string]any{"support_attributes": []string{"STABLE"}},
			"container":          map[string]any{"image_digest": imageDigest},
		},
	}
	tests := []struct {
		name    string
		mutate  func(map[string]any)
		wantErr string
	}{
		{name: "valid"},
		{name: "expired", mutate: func(c map[string]any) { c["exp"] = time.Now().Add(-time.Minute).Unix() }, wantErr: "expired"},
		{name: "wrong software", mutate: func(c map[string]any) { c["swname"] = "ORDINARY_VM" }, wantErr: "swname"},
		{name: "debug enabled", mutate: func(c map[string]any) { c["dbgstat"] = "enabled" }, wantErr: "dbgstat"},
		{name: "wrong image", mutate: func(c map[string]any) {
			c["submods"].(map[string]any)["container"] = map[string]any{"image_digest": "sha256:wrong"}
		}, wantErr: "image_digest"},
		{name: "wrong service account", mutate: func(c map[string]any) { c["google_service_accounts"] = []string{"other@example.com"} }, wantErr: "service account"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := json.Marshal(validClaims)
			if err != nil {
				t.Fatal(err)
			}
			var claims map[string]any
			if err := json.Unmarshal(encoded, &claims); err != nil {
				t.Fatal(err)
			}
			if tt.mutate != nil {
				tt.mutate(claims)
			}
			payload, err := json.Marshal(claims)
			if err != nil {
				t.Fatal(err)
			}
			tokenPath := filepath.Join(t.TempDir(), "claims.jwt")
			token := "e30." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
			if err := os.WriteFile(tokenPath, []byte(token), 0o600); err != nil {
				t.Fatal(err)
			}
			err = (gcpConfidentialSpaceAttestation{
				tokenFile: tokenPath, expectedImageDigest: imageDigest, expectedServiceAccount: serviceAccount,
			}).Validate()
			if tt.wantErr == "" && err != nil {
				t.Fatalf("valid attestation: %v", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("Validate error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}
