package agentstate

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	EnvKeyProvider          = "LAYERV_KEY_PROVIDER"
	sealedPrivateKeyVersion = 1

	KeyProviderFile                 = "file"
	KeyProviderAWSKMS               = "aws-kms"
	KeyProviderGCPKMS               = "gcp-kms"
	KeyProviderAWSNitro             = "aws-nitro"
	KeyProviderGCPConfidentialSpace = "gcp-confidential-space"
	// KeyProviderLocalKey wraps the complete qurl-go state DEK with a stable
	// per-profile key supplied by the external qURL Desktop orchestrator from
	// its OS keystore.
	// The key bytes arrive through an inherited anonymous descriptor and never
	// belong in argv, environment values, or a disk file.
	KeyProviderLocalKey = "local-key"

	// EnvLocalKeyFD names the inherited pipe or connected local socket
	// containing exactly one 32-byte local wrapping key. The external qURL
	// Desktop app's Electron runtime implements its child-process "pipe" as an
	// AF_UNIX socketpair on Unix. The descriptor number is public metadata.
	EnvLocalKeyFD = "LAYERV_LOCAL_KEY_FD"

	// Legacy only: used by the pre-mutation state guard, never written.
	SealedPrivateKeyFile = "private_key.sealed.json"

	EnvAWSKMSKeyID                         = "LAYERV_AWS_KMS_KEY_ID"
	EnvAWSKMSRegion                        = "LAYERV_AWS_KMS_REGION"
	EnvAWSNitroAttestationDocumentFile     = "LAYERV_AWS_NITRO_ATTESTATION_DOCUMENT_FILE"
	EnvAWSNitroAttestationDocumentEncoding = "LAYERV_AWS_NITRO_ATTESTATION_DOCUMENT_ENCODING"
	EnvAWSNitroRecipientUnwrapCommand      = "LAYERV_AWS_NITRO_RECIPIENT_UNWRAP_COMMAND"
	EnvGCPKMSKeyName                       = "LAYERV_GCP_KMS_KEY_NAME"
	EnvGCPConfidentialSpaceTokenFile       = "LAYERV_GCP_CONFIDENTIAL_SPACE_TOKEN_FILE" //nolint:gosec
	EnvGCPConfidentialSpaceImageDigest     = "LAYERV_GCP_CONFIDENTIAL_SPACE_IMAGE_DIGEST"
	EnvGCPConfidentialSpaceServiceAccount  = "LAYERV_GCP_CONFIDENTIAL_SPACE_SERVICE_ACCOUNT"

	keyProviderTimeout = 30 * time.Second
)

var keyProviderForName = defaultKeyProviderForName

// KeyProvider is the existing cloud envelope boundary. qurl-go owns the full
// state format; sdkStateKeyWrapper passes only its random 32-byte DEK here.
type KeyProvider interface {
	Name() string
	Seal(context.Context, []byte, map[string]string) (SealedPrivateKey, error)
	Unseal(context.Context, SealedPrivateKey) ([]byte, error)
}

type SealedPrivateKey struct {
	Version           int               `json:"version"`
	Provider          string            `json:"provider"`
	KeyID             string            `json:"key_id"`
	Region            string            `json:"region,omitempty"`
	CiphertextBase64  string            `json:"ciphertext_b64"`
	EncryptionContext map[string]string `json:"encryption_context,omitempty"`
	CreatedAt         string            `json:"created_at"`
}

func selectedKeyProviderName() (string, error) {
	name := strings.ToLower(strings.TrimSpace(os.Getenv(EnvKeyProvider)))
	if name == "" {
		return KeyProviderFile, nil
	}
	switch name {
	case KeyProviderFile, KeyProviderAWSKMS, KeyProviderGCPKMS, KeyProviderAWSNitro, KeyProviderGCPConfidentialSpace, KeyProviderLocalKey:
		return name, nil
	default:
		return "", fmt.Errorf("%s must be one of %s, %s, %s, %s, %s, %s; got %q", EnvKeyProvider, KeyProviderFile, KeyProviderAWSKMS, KeyProviderGCPKMS, KeyProviderAWSNitro, KeyProviderGCPConfidentialSpace, KeyProviderLocalKey, name)
	}
}

func defaultKeyProviderForName(name string) (KeyProvider, error) {
	switch name {
	case KeyProviderAWSKMS:
		return newAWSKMSKeyProviderFromEnv()
	case KeyProviderGCPKMS:
		return newGCPKMSKeyProviderFromEnv()
	case KeyProviderAWSNitro:
		return newAWSNitroKeyProviderFromEnv()
	case KeyProviderGCPConfidentialSpace:
		return newGCPConfidentialSpaceKeyProviderFromEnv()
	case KeyProviderLocalKey:
		return newLocalKeyProviderFromEnv()
	default:
		return nil, fmt.Errorf("unsupported envelope key provider %q", name)
	}
}

func sealedCiphertextBytes(sealed SealedPrivateKey) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(sealed.CiphertextBase64)
	if err != nil {
		return nil, fmt.Errorf("decode sealed ciphertext: %w", err)
	}
	if len(decoded) == 0 {
		return nil, fmt.Errorf("decode sealed ciphertext: ciphertext is empty")
	}
	return decoded, nil
}

func sealedCiphertextRecord(provider, keyID string, ciphertext []byte, encContext map[string]string) SealedPrivateKey {
	return SealedPrivateKey{
		Version: sealedPrivateKeyVersion, Provider: provider, KeyID: keyID,
		CiphertextBase64:  base64.StdEncoding.EncodeToString(ciphertext),
		EncryptionContext: encContext, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
}

func scrubBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
