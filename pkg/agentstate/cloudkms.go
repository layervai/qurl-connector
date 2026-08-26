package agentstate

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	kms "cloud.google.com/go/kms/apiv1"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	awskmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	gax "github.com/googleapis/gax-go/v2"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const defaultGCPConfidentialSpaceTokenFile = "/run/container_launcher/attestation_verifier_claims_token"

const gcpConfidentialSpaceTokenExpiryLeeway = 30 * time.Second
const maxAWSNitroRecipientUnwrapOutput = 4 * 1024

type awsKMSClient interface {
	Encrypt(context.Context, *awskms.EncryptInput, ...func(*awskms.Options)) (*awskms.EncryptOutput, error)
	Decrypt(context.Context, *awskms.DecryptInput, ...func(*awskms.Options)) (*awskms.DecryptOutput, error)
}

type gcpKMSClient interface {
	Encrypt(context.Context, *kmspb.EncryptRequest, ...gax.CallOption) (*kmspb.EncryptResponse, error)
	Decrypt(context.Context, *kmspb.DecryptRequest, ...gax.CallOption) (*kmspb.DecryptResponse, error)
	Close() error
}

var (
	newAWSKMSClient = func(ctx context.Context, region string) (awsKMSClient, string, error) {
		opts := []func(*awscfg.LoadOptions) error{}
		if region != "" {
			opts = append(opts, awscfg.WithRegion(region))
		}
		cfg, err := awscfg.LoadDefaultConfig(ctx, opts...)
		if err != nil {
			return nil, "", fmt.Errorf("load aws config: %w", err)
		}
		return awskms.NewFromConfig(cfg), cfg.Region, nil
	}

	newGCPKMSClient = func(ctx context.Context) (gcpKMSClient, error) {
		return kms.NewKeyManagementClient(ctx)
	}
)

type awsKMSKeyProvider struct {
	keyID        string
	region       string
	providerName string
}

func newAWSKMSKeyProviderFromEnv() (KeyProvider, error) {
	keyID := strings.TrimSpace(os.Getenv(EnvAWSKMSKeyID))
	if keyID == "" {
		return nil, fmt.Errorf("%s=%s requires %s", EnvKeyProvider, KeyProviderAWSKMS, EnvAWSKMSKeyID)
	}
	return awsKMSKeyProvider{
		keyID:  keyID,
		region: strings.TrimSpace(os.Getenv(EnvAWSKMSRegion)),
	}, nil
}

func (p awsKMSKeyProvider) Name() string {
	if p.providerName != "" {
		return p.providerName
	}
	return KeyProviderAWSKMS
}

func (p awsKMSKeyProvider) Seal(ctx context.Context, plaintext []byte, encContext map[string]string) (SealedPrivateKey, error) {
	client, region, err := p.client(ctx, "")
	if err != nil {
		return SealedPrivateKey{}, err
	}
	if region == "" {
		return SealedPrivateKey{}, fmt.Errorf("aws kms region could not be resolved; set %s or AWS_REGION before sealing the native state DEK", EnvAWSKMSRegion)
	}
	out, err := client.Encrypt(ctx, &awskms.EncryptInput{
		KeyId:             aws.String(p.keyID),
		Plaintext:         plaintext,
		EncryptionContext: encContext,
	})
	if err != nil {
		return SealedPrivateKey{}, fmt.Errorf("aws kms encrypt: %w", err)
	}
	// Unlike GCP Cloud KMS, AWS KMS does not expose per-field CRC echoes here;
	// the SDK/HTTP stack owns transport integrity, so we validate response shape.
	if out == nil {
		return SealedPrivateKey{}, fmt.Errorf("aws kms encrypt returned nil response")
	}
	if len(out.CiphertextBlob) == 0 {
		return SealedPrivateKey{}, fmt.Errorf("aws kms encrypt returned empty ciphertext")
	}
	sealed := sealedCiphertextRecord(p.Name(), p.keyID, out.CiphertextBlob, encContext)
	sealed.Region = region
	return sealed, nil
}

func (p awsKMSKeyProvider) Unseal(ctx context.Context, sealed SealedPrivateKey) ([]byte, error) {
	if sealed.Provider != p.Name() {
		return nil, fmt.Errorf("sealed key provider %q does not match selected provider %q", sealed.Provider, p.Name())
	}
	ciphertext, err := sealedCiphertextBytes(sealed)
	if err != nil {
		return nil, err
	}
	client, _, err := p.client(ctx, strings.TrimSpace(sealed.Region))
	if err != nil {
		return nil, err
	}
	out, err := client.Decrypt(ctx, &awskms.DecryptInput{
		CiphertextBlob:    ciphertext,
		EncryptionContext: sealed.EncryptionContext,
		KeyId:             aws.String(sealed.KeyID),
	})
	if err != nil {
		return nil, fmt.Errorf("aws kms decrypt: %w", err)
	}
	// Unlike GCP Cloud KMS, AWS KMS does not expose per-field CRC echoes here;
	// the SDK/HTTP stack owns transport integrity, so we validate response shape.
	if out == nil {
		return nil, fmt.Errorf("aws kms decrypt returned nil response")
	}
	plaintext := out.Plaintext
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("aws kms decrypt returned empty plaintext")
	}
	return plaintext, nil
}

func (p awsKMSKeyProvider) client(ctx context.Context, region string) (awsKMSClient, string, error) {
	// KMS operations are startup-only. Build clients per operation so the
	// provider stays stateless; sdkStateKeyWrapper supplies the
	// keyProviderTimeout-bounded context for config/credential resolution and
	// the network call.
	if region == "" {
		region = p.region
	}
	return newAWSKMSClient(ctx, region)
}

type gcpKMSKeyProvider struct {
	keyName      string
	providerName string
}

func newGCPKMSKeyProviderFromEnv() (KeyProvider, error) {
	keyName := strings.TrimSpace(os.Getenv(EnvGCPKMSKeyName))
	if keyName == "" {
		return nil, fmt.Errorf("%s=%s requires %s", EnvKeyProvider, KeyProviderGCPKMS, EnvGCPKMSKeyName)
	}
	return gcpKMSKeyProvider{keyName: keyName}, nil
}

func (p gcpKMSKeyProvider) Name() string {
	if p.providerName != "" {
		return p.providerName
	}
	return KeyProviderGCPKMS
}

func (p gcpKMSKeyProvider) Seal(ctx context.Context, plaintext []byte, encContext map[string]string) (SealedPrivateKey, error) {
	// KMS operations are startup-only. Build clients per operation so the
	// provider stays stateless; sdkStateKeyWrapper supplies the
	// keyProviderTimeout-bounded context for connection setup and the RPC.
	client, err := newGCPKMSClient(ctx)
	if err != nil {
		return SealedPrivateKey{}, fmt.Errorf("create gcp kms client: %w", err)
	}
	defer closeGCPKMSClient(client)

	aad, err := encryptionContextAAD(encContext)
	if err != nil {
		return SealedPrivateKey{}, err
	}
	req := gcpEncryptRequest(p.keyName, plaintext, aad)
	out, err := client.Encrypt(ctx, req)
	if err != nil {
		return SealedPrivateKey{}, fmt.Errorf("gcp kms encrypt: %w", err)
	}
	if err := validateGCPEncryptResponse(out, aad); err != nil {
		return SealedPrivateKey{}, err
	}
	return sealedCiphertextRecord(p.Name(), p.keyName, out.Ciphertext, encContext), nil
}

func (p gcpKMSKeyProvider) Unseal(ctx context.Context, sealed SealedPrivateKey) ([]byte, error) {
	if sealed.Provider != p.Name() {
		return nil, fmt.Errorf("sealed key provider %q does not match selected provider %q", sealed.Provider, p.Name())
	}
	ciphertext, err := sealedCiphertextBytes(sealed)
	if err != nil {
		return nil, err
	}
	keyName := strings.TrimSpace(sealed.KeyID)
	if keyName == "" {
		keyName = p.keyName
	}
	// KMS operations are startup-only. Build clients per operation so the
	// provider stays stateless; sdkStateKeyWrapper supplies the
	// keyProviderTimeout-bounded context for connection setup and the RPC.
	client, err := newGCPKMSClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("create gcp kms client: %w", err)
	}
	defer closeGCPKMSClient(client)

	aad, err := encryptionContextAAD(sealed.EncryptionContext)
	if err != nil {
		return nil, err
	}
	req := gcpDecryptRequest(keyName, ciphertext, aad)
	out, err := client.Decrypt(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("gcp kms decrypt: %w", err)
	}
	if err := validateGCPDecryptResponse(out); err != nil {
		if out != nil {
			scrubBytes(out.Plaintext)
		}
		return nil, err
	}
	return out.Plaintext, nil
}

func encryptionContextAAD(encContext map[string]string) ([]byte, error) {
	if len(encContext) == 0 {
		return nil, nil
	}
	// encoding/json emits map keys in deterministic sorted order, which keeps
	// seal and unseal AAD byte-identical for the same flat map[string]string
	// context. If the context ever stops being flat, add versioned migration
	// tests before changing this encoding.
	data, err := json.Marshal(encContext)
	if err != nil {
		return nil, fmt.Errorf("marshal encryption context AAD: %w", err)
	}
	return data, nil
}

func closeGCPKMSClient(client gcpKMSClient) {
	if err := client.Close(); err != nil {
		slog.Debug("could not close gcp kms client", "err", err)
	}
}

var gcpCRC32CTable = crc32.MakeTable(crc32.Castagnoli)

func gcpEncryptRequest(keyName string, plaintext, aad []byte) *kmspb.EncryptRequest {
	req := &kmspb.EncryptRequest{
		Name:                        keyName,
		Plaintext:                   plaintext,
		AdditionalAuthenticatedData: aad,
		PlaintextCrc32C:             gcpCRC32CValue(plaintext),
	}
	if len(aad) > 0 {
		req.AdditionalAuthenticatedDataCrc32C = gcpCRC32CValue(aad)
	}
	return req
}

func gcpDecryptRequest(keyName string, ciphertext, aad []byte) *kmspb.DecryptRequest {
	req := &kmspb.DecryptRequest{
		Name:       keyName,
		Ciphertext: ciphertext,
		// This KMS SDK version reports decrypt request CRC mismatches as RPC
		// errors rather than DecryptResponse verified booleans, so set the
		// request CRCs here and validate the returned plaintext CRC below.
		CiphertextCrc32C:            gcpCRC32CValue(ciphertext),
		AdditionalAuthenticatedData: aad,
	}
	if len(aad) > 0 {
		req.AdditionalAuthenticatedDataCrc32C = gcpCRC32CValue(aad)
	}
	return req
}

func validateGCPEncryptResponse(out *kmspb.EncryptResponse, aad []byte) error {
	if out == nil {
		return fmt.Errorf("gcp kms encrypt returned nil response")
	}
	if !out.GetVerifiedPlaintextCrc32C() {
		return fmt.Errorf("gcp kms encrypt did not verify plaintext crc32c")
	}
	if len(aad) > 0 && !out.GetVerifiedAdditionalAuthenticatedDataCrc32C() {
		return fmt.Errorf("gcp kms encrypt did not verify AAD crc32c")
	}
	if len(out.GetCiphertext()) == 0 {
		return fmt.Errorf("gcp kms encrypt returned empty ciphertext")
	}
	if !gcpCRC32CMatches(out.GetCiphertext(), out.GetCiphertextCrc32C()) {
		return fmt.Errorf("gcp kms encrypt ciphertext crc32c mismatch")
	}
	return nil
}

func validateGCPDecryptResponse(out *kmspb.DecryptResponse) error {
	if out == nil {
		return fmt.Errorf("gcp kms decrypt returned nil response")
	}
	if len(out.GetPlaintext()) == 0 {
		return fmt.Errorf("gcp kms decrypt returned empty plaintext")
	}
	if !gcpCRC32CMatches(out.GetPlaintext(), out.GetPlaintextCrc32C()) {
		return fmt.Errorf("gcp kms decrypt plaintext crc32c mismatch")
	}
	return nil
}

func gcpCRC32CValue(data []byte) *wrapperspb.Int64Value {
	return wrapperspb.Int64(int64(crc32.Checksum(data, gcpCRC32CTable)))
}

func gcpCRC32CMatches(data []byte, want *wrapperspb.Int64Value) bool {
	if want == nil {
		return false
	}
	return int64(crc32.Checksum(data, gcpCRC32CTable)) == want.Value
}

type awsNitroKeyProvider struct {
	// KMS Encrypt has no Recipient mode; qurl-go's sealed state store validates
	// the wrapped DEK through this provider's attested Unseal before commit.
	awsKMSKeyProvider
	attestationDocument       []byte
	unwrapRecipientCiphertext func(context.Context, []byte) ([]byte, error)
}

func newAWSNitroKeyProviderFromEnv() (KeyProvider, error) {
	keyID := strings.TrimSpace(os.Getenv(EnvAWSKMSKeyID))
	if keyID == "" {
		return nil, fmt.Errorf("%s=%s requires %s", EnvKeyProvider, KeyProviderAWSNitro, EnvAWSKMSKeyID)
	}
	attestationPath := strings.TrimSpace(os.Getenv(EnvAWSNitroAttestationDocumentFile))
	if attestationPath == "" {
		return nil, fmt.Errorf("%s=%s requires %s", EnvKeyProvider, KeyProviderAWSNitro, EnvAWSNitroAttestationDocumentFile)
	}
	// KMS operations are startup-only today (state open and first save), so
	// each process start snapshots the freshly produced attestation document.
	// If runtime KMS calls are added later, re-read or refresh the document at
	// decrypt time instead of reusing this construction-time snapshot.
	attestationDocument, err := readAWSNitroAttestationDocument(
		attestationPath,
		strings.TrimSpace(os.Getenv(EnvAWSNitroAttestationDocumentEncoding)),
	)
	if err != nil {
		return nil, err
	}
	unwrapCommand := strings.TrimSpace(os.Getenv(EnvAWSNitroRecipientUnwrapCommand))
	if unwrapCommand == "" {
		return nil, fmt.Errorf("%s=%s requires %s", EnvKeyProvider, KeyProviderAWSNitro, EnvAWSNitroRecipientUnwrapCommand)
	}
	unwrap, err := awsNitroRecipientUnwrapCommand(unwrapCommand)
	if err != nil {
		return nil, err
	}
	return awsNitroKeyProvider{
		awsKMSKeyProvider: awsKMSKeyProvider{
			keyID:        keyID,
			region:       strings.TrimSpace(os.Getenv(EnvAWSKMSRegion)),
			providerName: KeyProviderAWSNitro,
		},
		attestationDocument:       attestationDocument,
		unwrapRecipientCiphertext: unwrap,
	}, nil
}

func (p awsNitroKeyProvider) Unseal(ctx context.Context, sealed SealedPrivateKey) ([]byte, error) {
	if sealed.Provider != p.Name() {
		return nil, fmt.Errorf("sealed key provider %q does not match selected provider %q", sealed.Provider, p.Name())
	}
	if len(p.attestationDocument) == 0 {
		return nil, fmt.Errorf("%s attestation document is empty", KeyProviderAWSNitro)
	}
	if p.unwrapRecipientCiphertext == nil {
		return nil, fmt.Errorf("%s recipient unwrap command is not configured", KeyProviderAWSNitro)
	}
	ciphertext, err := sealedCiphertextBytes(sealed)
	if err != nil {
		return nil, err
	}
	client, _, err := p.client(ctx, strings.TrimSpace(sealed.Region))
	if err != nil {
		return nil, err
	}
	out, err := client.Decrypt(ctx, &awskms.DecryptInput{
		CiphertextBlob:    ciphertext,
		EncryptionContext: sealed.EncryptionContext,
		KeyId:             aws.String(sealed.KeyID),
		Recipient: &awskmstypes.RecipientInfo{
			AttestationDocument:    p.attestationDocument,
			KeyEncryptionAlgorithm: awskmstypes.KeyEncryptionMechanismRsaesOaepSha256,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("aws nitro kms decrypt: %w", err)
	}
	if out == nil {
		return nil, fmt.Errorf("aws nitro kms decrypt returned nil response")
	}
	if len(out.Plaintext) != 0 {
		scrubBytes(out.Plaintext)
		return nil, fmt.Errorf("aws nitro kms decrypt returned host plaintext; expected attested CiphertextForRecipient")
	}
	if len(out.CiphertextForRecipient) == 0 {
		return nil, fmt.Errorf("aws nitro kms decrypt returned empty CiphertextForRecipient")
	}
	plaintext, err := p.unwrapRecipientCiphertext(ctx, out.CiphertextForRecipient)
	if err != nil {
		return nil, fmt.Errorf("aws nitro recipient unwrap: %w", err)
	}
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("aws nitro recipient unwrap returned empty plaintext")
	}
	if len(plaintext) != StateDEKSize {
		scrubBytes(plaintext)
		return nil, fmt.Errorf("aws nitro recipient unwrap returned state DEK size %d, want %d", len(plaintext), StateDEKSize)
	}
	return plaintext, nil
}

func readAWSNitroAttestationDocument(path, encoding string) ([]byte, error) {
	// Operator-configured Nitro attestation document path; no search path or
	// shell expansion happens here.
	//nolint:gosec
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", EnvAWSNitroAttestationDocumentFile, err)
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("%s is empty", EnvAWSNitroAttestationDocumentFile)
	}
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "raw":
		return data, nil
	case "auto":
		// Auto is an operator convenience only: arbitrary raw bytes that also
		// happen to be valid base64 text are indistinguishable here and will be
		// decoded. Production deployments should set raw or base64 explicitly.
		if decoded, err := base64.StdEncoding.DecodeString(string(trimmed)); err == nil && len(decoded) > 0 {
			return decoded, nil
		}
		return data, nil
	case "base64":
		decoded, err := base64.StdEncoding.DecodeString(string(trimmed))
		if err != nil {
			return nil, fmt.Errorf("decode %s as base64: %w", EnvAWSNitroAttestationDocumentFile, err)
		}
		if len(decoded) == 0 {
			return nil, fmt.Errorf("%s decoded to empty attestation document", EnvAWSNitroAttestationDocumentFile)
		}
		return decoded, nil
	default:
		return nil, fmt.Errorf("%s must be one of auto, raw, or base64", EnvAWSNitroAttestationDocumentEncoding)
	}
}

func awsNitroRecipientUnwrapCommand(command string) (func(context.Context, []byte) ([]byte, error), error) {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return nil, fmt.Errorf("%s is empty", EnvAWSNitroRecipientUnwrapCommand)
	}
	if _, err := exec.LookPath(parts[0]); err != nil {
		return nil, fmt.Errorf("%s executable %q: %w", EnvAWSNitroRecipientUnwrapCommand, parts[0], err)
	}
	return func(ctx context.Context, ciphertext []byte) ([]byte, error) {
		// Operator-configured attested unwrap helper. This intentionally executes
		// the selected binary without a shell so args are not re-interpreted.
		//nolint:gosec
		cmd := exec.CommandContext(ctx, parts[0], parts[1:]...)
		cmd.Stdin = bytes.NewReader(ciphertext)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return nil, fmt.Errorf("%s stdout pipe: %w", EnvAWSNitroRecipientUnwrapCommand, err)
		}
		if err := cmd.Start(); err != nil {
			return nil, fmt.Errorf("%s start: %w", EnvAWSNitroRecipientUnwrapCommand, err)
		}
		out, stdoutTooLarge, readErr := readBoundedCommandOutput(stdout, maxAWSNitroRecipientUnwrapOutput)
		waitErr := cmd.Wait()
		if readErr != nil {
			scrubBytes(out)
			return nil, fmt.Errorf("%s read stdout: %w%s", EnvAWSNitroRecipientUnwrapCommand, readErr, commandStderrSuffix(stderr.Bytes()))
		}
		if stdoutTooLarge {
			scrubBytes(out)
			return nil, fmt.Errorf("%s stdout exceeded %d bytes%s", EnvAWSNitroRecipientUnwrapCommand, maxAWSNitroRecipientUnwrapOutput, commandStderrSuffix(stderr.Bytes()))
		}
		if waitErr != nil {
			scrubBytes(out)
			return nil, fmt.Errorf("%s failed: %w%s", EnvAWSNitroRecipientUnwrapCommand, waitErr, commandStderrSuffix(stderr.Bytes()))
		}
		return out, nil
	}, nil
}

func readBoundedCommandOutput(r io.Reader, maxBytes int64) ([]byte, bool, error) {
	out, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return out, false, err
	}
	tooLarge := int64(len(out)) > maxBytes
	if tooLarge {
		_, err = io.Copy(io.Discard, r)
	}
	return out, tooLarge, err
}

func commandStderrSuffix(stderr []byte) string {
	msg := strings.TrimSpace(strings.ToValidUTF8(string(stderr), "\uFFFD"))
	if msg == "" {
		return ""
	}
	const maxStderr = 512
	if len(msg) > maxStderr {
		end := maxStderr
		for end > 0 && !utf8.RuneStart(msg[end]) {
			end--
		}
		if end == 0 {
			end = maxStderr
		}
		msg = msg[:end] + "...(truncated)"
	}
	return ": " + msg
}

type gcpConfidentialSpaceKeyProvider struct {
	gcpKMSKeyProvider
	attestation gcpConfidentialSpaceAttestation
}

type gcpConfidentialSpaceAttestation struct {
	tokenFile              string
	expectedImageDigest    string
	expectedServiceAccount string
}

type gcpConfidentialSpaceClaims struct {
	ExpiresAt             int64    `json:"exp"`
	SWName                string   `json:"swname"`
	DebugStatus           string   `json:"dbgstat"`
	GoogleServiceAccounts []string `json:"google_service_accounts"`
	Submods               struct {
		ConfidentialSpace struct {
			SupportAttributes []string `json:"support_attributes"`
		} `json:"confidential_space"`
		Container struct {
			ImageDigest string `json:"image_digest"`
		} `json:"container"`
	} `json:"submods"`
}

func newGCPConfidentialSpaceKeyProviderFromEnv() (KeyProvider, error) {
	keyName := strings.TrimSpace(os.Getenv(EnvGCPKMSKeyName))
	if keyName == "" {
		return nil, fmt.Errorf("%s=%s requires %s", EnvKeyProvider, KeyProviderGCPConfidentialSpace, EnvGCPKMSKeyName)
	}
	tokenFile := strings.TrimSpace(os.Getenv(EnvGCPConfidentialSpaceTokenFile))
	if tokenFile == "" {
		tokenFile = defaultGCPConfidentialSpaceTokenFile
	}
	attestation := gcpConfidentialSpaceAttestation{
		tokenFile:              tokenFile,
		expectedImageDigest:    strings.TrimSpace(os.Getenv(EnvGCPConfidentialSpaceImageDigest)),
		expectedServiceAccount: strings.TrimSpace(os.Getenv(EnvGCPConfidentialSpaceServiceAccount)),
	}
	if err := attestation.Validate(); err != nil {
		return nil, err
	}
	slog.Info(
		"gcp confidential space local attestation checks passed; Cloud KMS key release is enforced by Workload Identity/IAM policy",
		"provider", KeyProviderGCPConfidentialSpace,
		"token_file", tokenFile,
	)
	return gcpConfidentialSpaceKeyProvider{
		gcpKMSKeyProvider: gcpKMSKeyProvider{
			keyName:      keyName,
			providerName: KeyProviderGCPConfidentialSpace,
		},
		attestation: attestation,
	}, nil
}

func (p gcpConfidentialSpaceKeyProvider) Seal(ctx context.Context, plaintext []byte, encContext map[string]string) (SealedPrivateKey, error) {
	if err := p.attestation.Validate(); err != nil {
		return SealedPrivateKey{}, err
	}
	return p.gcpKMSKeyProvider.Seal(ctx, plaintext, encContext)
}

func (p gcpConfidentialSpaceKeyProvider) Unseal(ctx context.Context, sealed SealedPrivateKey) ([]byte, error) {
	if err := p.attestation.Validate(); err != nil {
		return nil, err
	}
	return p.gcpKMSKeyProvider.Unseal(ctx, sealed)
}

func (a gcpConfidentialSpaceAttestation) Validate() error {
	tokenFile := strings.TrimSpace(a.tokenFile)
	if tokenFile == "" {
		tokenFile = defaultGCPConfidentialSpaceTokenFile
	}
	expectedImageDigest := strings.TrimSpace(a.expectedImageDigest)
	if expectedImageDigest == "" {
		return fmt.Errorf("%s=%s requires %s", EnvKeyProvider, KeyProviderGCPConfidentialSpace, EnvGCPConfidentialSpaceImageDigest)
	}
	expectedServiceAccount := strings.TrimSpace(a.expectedServiceAccount)
	if expectedServiceAccount == "" {
		return fmt.Errorf("%s=%s requires %s", EnvKeyProvider, KeyProviderGCPConfidentialSpace, EnvGCPConfidentialSpaceServiceAccount)
	}
	// This is a local fail-fast claim check, not a JWT verifier: signature,
	// audience, and key-release decisions stay with Confidential Space WIF/IAM
	// and Cloud KMS.
	tokenBytes, err := os.ReadFile(tokenFile)
	if err != nil {
		return fmt.Errorf("read %s: %w", EnvGCPConfidentialSpaceTokenFile, err)
	}
	claims, err := parseGCPConfidentialSpaceClaims(strings.TrimSpace(string(tokenBytes)))
	if err != nil {
		return err
	}
	if claims.ExpiresAt == 0 {
		return fmt.Errorf("gcp confidential space attestation missing exp claim")
	}
	// Deliberately accept a small amount of expiry skew for token-file freshness
	// races between Confidential Space and this process.
	if claims.ExpiresAt+int64(gcpConfidentialSpaceTokenExpiryLeeway.Seconds()) <= time.Now().Unix() {
		return fmt.Errorf("gcp confidential space attestation expired at %d", claims.ExpiresAt)
	}
	if claims.SWName != "CONFIDENTIAL_SPACE" {
		return fmt.Errorf("gcp confidential space attestation swname = %q, want CONFIDENTIAL_SPACE", claims.SWName)
	}
	if claims.DebugStatus != "disabled-since-boot" {
		return fmt.Errorf("gcp confidential space debug status dbgstat = %q, want disabled-since-boot", claims.DebugStatus)
	}
	if !slices.Contains(claims.Submods.ConfidentialSpace.SupportAttributes, "STABLE") {
		return fmt.Errorf("gcp confidential space attestation missing STABLE support attribute")
	}
	if claims.Submods.Container.ImageDigest != expectedImageDigest {
		return fmt.Errorf("gcp confidential space image_digest = %q, want %q", claims.Submods.Container.ImageDigest, expectedImageDigest)
	}
	if !slices.Contains(claims.GoogleServiceAccounts, expectedServiceAccount) {
		return fmt.Errorf("gcp confidential space service account %q missing from attestation", expectedServiceAccount)
	}
	return nil
}

func parseGCPConfidentialSpaceClaims(token string) (gcpConfidentialSpaceClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return gcpConfidentialSpaceClaims{}, fmt.Errorf("%s must contain a JWT attestation token", EnvGCPConfidentialSpaceTokenFile)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return gcpConfidentialSpaceClaims{}, fmt.Errorf("decode gcp confidential space attestation token payload: %w", err)
	}
	var claims gcpConfidentialSpaceClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return gcpConfidentialSpaceClaims{}, fmt.Errorf("parse gcp confidential space attestation token claims: %w", err)
	}
	return claims, nil
}
