// Package policy implements OTA policy distribution for DefenseClaw edge devices.
// It compiles YAML policies into the binary blob format expected by the C-side
// OTA receiver (edge-connector/src/comms/ota_receiver.c), signs them with
// HMAC-SHA256, and distributes via MQTT.
package policy

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
)

// Signer signs and verifies policy blobs before OTA delivery.
type Signer interface {
	// Sign produces a signature over the given data.
	Sign(data []byte) ([]byte, error)

	// Verify checks that signature is valid for data.
	Verify(data, signature []byte) error
}

// HMACSigner implements HMAC-SHA256 signing, matching the C-side fallback
// verification path in ota_receiver.c.
type HMACSigner struct {
	key []byte
}

// NewHMACSigner creates a signer from the given key bytes.
// The key should be at least 32 bytes for adequate security.
func NewHMACSigner(key []byte) (*HMACSigner, error) {
	if len(key) == 0 {
		return nil, errors.New("signing key must not be empty")
	}
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	return &HMACSigner{key: keyCopy}, nil
}

// NewHMACSignerFromEnv creates a signer using the hex-encoded key from the
// DCLAW_OTA_KEY environment variable (matching the C-side ota_receiver.c).
// Falls back to a 32-byte all-zero key if the env var is not set, matching
// the C-side development fallback for interoperability.
func NewHMACSignerFromEnv() (*HMACSigner, error) {
	keyHex := os.Getenv("DCLAW_OTA_KEY")
	if keyHex == "" {
		// Development fallback — all-zero key, matching C-side ota_receiver.c
		// get_ota_ca_key() which memsets to zero when DCLAW_OTA_KEY is unset.
		devKey := make([]byte, 32)
		return &HMACSigner{key: devKey}, nil
	}

	key, err := decodeHex(keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid DCLAW_OTA_KEY: %w", err)
	}
	return NewHMACSigner(key)
}

// Sign produces a 32-byte HMAC-SHA256 signature over the data.
func (s *HMACSigner) Sign(data []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, s.key)
	mac.Write(data)
	return mac.Sum(nil), nil
}

// Verify checks the HMAC-SHA256 signature.
func (s *HMACSigner) Verify(data, signature []byte) error {
	mac := hmac.New(sha256.New, s.key)
	mac.Write(data)
	expected := mac.Sum(nil)
	if !hmac.Equal(expected, signature) {
		return errors.New("HMAC signature verification failed")
	}
	return nil
}

// decodeHex decodes a hex-encoded string to bytes.
func decodeHex(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("hex string has odd length: %d", len(s))
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		hi, err := hexVal(s[2*i])
		if err != nil {
			return nil, err
		}
		lo, err := hexVal(s[2*i+1])
		if err != nil {
			return nil, err
		}
		out[i] = hi<<4 | lo
	}
	return out, nil
}

func hexVal(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	default:
		return 0, fmt.Errorf("invalid hex character: %c", c)
	}
}
