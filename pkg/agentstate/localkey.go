package agentstate

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

const (
	localWrappingKeySize = 32
	localKeyRecordKeyID  = "local-key:v1"
)

type localKeyProvider struct {
	key []byte
}

var localKeyCache struct {
	sync.Mutex
	fd  string
	key []byte
}

func newLocalKeyProviderFromEnv() (KeyProvider, error) {
	fdValue := strings.TrimSpace(os.Getenv(EnvLocalKeyFD))
	if fdValue == "" {
		return nil, fmt.Errorf("%s=%s requires %s", EnvKeyProvider, KeyProviderLocalKey, EnvLocalKeyFD)
	}
	key, err := cachedLocalWrappingKey(fdValue)
	if err != nil {
		return nil, err
	}
	return newLocalKeyProviderOwned(key)
}

func cachedLocalWrappingKey(fdValue string) ([]byte, error) {
	localKeyCache.Lock()
	defer localKeyCache.Unlock()
	if localKeyCache.fd != fdValue || len(localKeyCache.key) == 0 {
		scrubBytes(localKeyCache.key)
		localKeyCache.fd = ""
		localKeyCache.key = nil
		key, err := readLocalWrappingKey(fdValue)
		if err != nil {
			// A failed inherited-descriptor read must not poison a retry after
			// an embedding process replaces that descriptor in place.
			return nil, err
		}
		localKeyCache.fd = fdValue
		localKeyCache.key = key
	}
	// A Connector process using local-key belongs to exactly one profile owned
	// by the external qURL Desktop app and never reuses this descriptor number
	// for a different key.
	// Clone under the lock so a concurrent descriptor switch cannot scrub the
	// returned buffer before the provider takes ownership.
	return append([]byte(nil), localKeyCache.key...), nil
}

func newLocalKeyProvider(key []byte) (localKeyProvider, error) {
	return newLocalKeyProviderOwned(append([]byte(nil), key...))
}

// newLocalKeyProviderOwned consumes a caller-owned key buffer. The inherited
// descriptor path already receives a cache-independent clone.
func newLocalKeyProviderOwned(key []byte) (localKeyProvider, error) {
	if len(key) != localWrappingKeySize {
		scrubBytes(key)
		return localKeyProvider{}, fmt.Errorf("local wrapping key has %d bytes (want %d)", len(key), localWrappingKeySize)
	}
	return localKeyProvider{key: key}, nil
}

func (p localKeyProvider) Name() string {
	return KeyProviderLocalKey
}

func (p localKeyProvider) Seal(_ context.Context, plaintext []byte, encContext map[string]string) (SealedPrivateKey, error) {
	aead, err := p.aead()
	if err != nil {
		return SealedPrivateKey{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return SealedPrivateKey{}, fmt.Errorf("generate local-key nonce: %w", err)
	}
	aad, err := encryptionContextAAD(encContext)
	if err != nil {
		return SealedPrivateKey{}, err
	}
	// Prefixing the nonce keeps CiphertextBase64 self-contained while the
	// state-envelope binding remains authenticated as AES-GCM AAD.
	ciphertext := aead.Seal(nonce, nonce, plaintext, aad)
	return sealedCiphertextRecord(p.Name(), localKeyRecordKeyID, ciphertext, encContext), nil
}

func (p localKeyProvider) Unseal(_ context.Context, sealed SealedPrivateKey) ([]byte, error) {
	if sealed.Provider != p.Name() {
		return nil, fmt.Errorf("sealed key provider %q does not match selected provider %q", sealed.Provider, p.Name())
	}
	if sealed.KeyID != localKeyRecordKeyID {
		return nil, fmt.Errorf("sealed local key id %q is unsupported", sealed.KeyID)
	}
	aead, err := p.aead()
	if err != nil {
		return nil, err
	}
	ciphertext, err := sealedCiphertextBytes(sealed)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aead.NonceSize()+aead.Overhead() {
		return nil, fmt.Errorf("local-key ciphertext is too short")
	}
	aad, err := encryptionContextAAD(sealed.EncryptionContext)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():], aad)
	if err != nil {
		return nil, fmt.Errorf("local-key AES-GCM authentication failed: %w", err)
	}
	return plaintext, nil
}

func (p localKeyProvider) aead() (cipher.AEAD, error) {
	block, err := aes.NewCipher(p.key)
	if err != nil {
		return nil, fmt.Errorf("initialize local-key AES-256: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize local-key AES-GCM: %w", err)
	}
	return aead, nil
}
