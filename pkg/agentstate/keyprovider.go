package agentstate

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
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
	// KeyProviderTPM seals the qurl-go state DEK to this machine's TPM 2.0.
	// It needs nothing from the environment, so a namespace whose sealed
	// envelope names it opens with LAYERV_KEY_PROVIDER unset, and a fresh
	// namespace selects it by default whenever ProbeTPM succeeds.
	KeyProviderTPM = "tpm"

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

// keyProviderNames lists every accepted LAYERV_KEY_PROVIDER value, in the
// order the error message names them. defaultKeyProviderForName must handle
// every name here except file.
var keyProviderNames = []string{
	KeyProviderFile, KeyProviderAWSKMS, KeyProviderGCPKMS, KeyProviderAWSNitro,
	KeyProviderGCPConfidentialSpace, KeyProviderLocalKey, KeyProviderTPM,
}

// explicitKeyProviderName returns the provider LAYERV_KEY_PROVIDER names, or
// "" when it is unset and the namespace decides.
func explicitKeyProviderName() (string, error) {
	name := strings.ToLower(strings.TrimSpace(os.Getenv(EnvKeyProvider)))
	if name == "" || knownKeyProvider(name) {
		return name, nil
	}
	return "", fmt.Errorf("%s must be one of %s; got %q", EnvKeyProvider, strings.Join(keyProviderNames, ", "), name)
}

func knownKeyProvider(name string) bool { return slices.Contains(keyProviderNames, name) }

// KeyProviderRequiresEnvironment reports whether a provider can only be
// constructed from LAYERV_KEY_PROVIDER and its companion variables. The file
// and tpm providers carry no key material in the environment, so a namespace
// using them can be served by a credential-free managed daemon.
func KeyProviderRequiresEnvironment(name string) bool {
	switch name {
	case KeyProviderFile, KeyProviderTPM:
		return false
	default:
		return true
	}
}

// defaultFreshKeyProvider is the provider a namespace holding no envelope uses
// when LAYERV_KEY_PROVIDER is unset: the TPM when this process can use one,
// otherwise the plaintext file. A TPM that exists but is not responding is an
// error rather than a plaintext fallback, because the choice is permanent for
// the namespace. Tests replace it to stay hermetic.
var defaultFreshKeyProvider = func() (string, error) {
	err := ProbeTPM()
	switch {
	case err == nil:
		return KeyProviderTPM, nil
	case errors.Is(err, ErrTPMNotResponding):
		return "", fmt.Errorf("%w; retry, or set %s=%s to create plaintext state", err, EnvKeyProvider, KeyProviderFile)
	case errors.Is(err, ErrTPMUnavailable):
		slog.Debug("no usable TPM; new agent state will be plaintext", "reason", err)
		return KeyProviderFile, nil
	default:
		// Plaintext is permanent for the namespace, so only a failure known to
		// be structural may choose it; anything unclassified fails closed.
		return "", err
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
	case KeyProviderTPM:
		return newTPMKeyProvider()
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
