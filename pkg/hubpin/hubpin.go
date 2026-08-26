// Package hubpin validates the X25519 public key that binds a configured Hub
// endpoint to its expected server identity.
package hubpin

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// DecodeServerPublicKeyB64 decodes a candidate Hub server public key and
// returns its raw bytes. A pinned trust root must have one byte spelling, so
// the input must be the canonical padded standard-base64 encoding of a
// canonical, usable X25519 public key; anything else is rejected. Error
// messages are phrased so callers can prefix the candidate's origin (an env
// var name, a repository-variable name) and read a sentence.
func DecodeServerPublicKeyB64(keyB64 string) ([]byte, error) {
	key, err := base64.StdEncoding.Strict().DecodeString(keyB64)
	if err != nil || base64.StdEncoding.EncodeToString(key) != keyB64 {
		return nil, errors.New("must be canonical padded standard base64")
	}
	if len(key) != curve25519.PointSize {
		return nil, fmt.Errorf("must encode a %d-byte X25519 public key", curve25519.PointSize)
	}
	if !canonicalPublicKey(key) {
		return nil, errors.New("must encode a canonical X25519 public key")
	}
	if _, err := curve25519.X25519(make([]byte, curve25519.ScalarSize), key); err != nil {
		return nil, fmt.Errorf("must encode a usable X25519 public key: %w", err)
	}
	return key, nil
}

func canonicalPublicKey(key []byte) bool {
	// X25519's field prime is 2^255-19, encoded little-endian as
	// ed ff ... ff 7f. RFC 7748 permits non-canonical inputs for generic
	// interoperability, but a pinned identity must have one byte spelling.
	for i := len(key) - 1; i >= 0; i-- {
		primeByte := byte(0xff)
		switch i {
		case 0:
			primeByte = 0xed
		case curve25519.PointSize - 1:
			primeByte = 0x7f
		}
		if key[i] != primeByte {
			return key[i] < primeByte
		}
	}
	return false
}

// FingerprintSHA256Hex returns the lowercase hex SHA-256 of the raw key bytes.
func FingerprintSHA256Hex(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:])
}
