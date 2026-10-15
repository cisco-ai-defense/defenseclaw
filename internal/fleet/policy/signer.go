// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

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

// HMACSigner implements HMAC-SHA256 signing for the explicitly provisioned
// OTA HMAC mode in ota_receiver.c.
type HMACSigner struct {
	key []byte
}

// NewHMACSigner creates a signer from the given key bytes.
// The wire protocol requires an independent, nonzero 32-byte secret.
func NewHMACSigner(key []byte) (*HMACSigner, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("HMAC key must be exactly 32 bytes, got %d", len(key))
	}
	allZero := true
	for _, b := range key {
		allZero = allZero && b == 0
	}
	if allZero {
		return nil, errors.New("HMAC key must not be all zero")
	}
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	return &HMACSigner{key: keyCopy}, nil
}

// NewHMACSignerFromEnv creates a signer using the hex-encoded key from the
// DCLAW_OTA_HMAC_KEY environment variable. DCLAW_OTA_KEY is reserved for an
// Ed25519 public verify key and must never be treated as an HMAC secret.
func NewHMACSignerFromEnv() (*HMACSigner, error) {
	keyHex := os.Getenv("DCLAW_OTA_HMAC_KEY")
	if keyHex == "" {
		return nil, errors.New("DCLAW_OTA_HMAC_KEY is required for HMAC policy signing")
	}

	key, err := decodeHex(keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid DCLAW_OTA_HMAC_KEY: %w", err)
	}
	return NewHMACSigner(key)
}

// NewEmergencySignerFromEnv creates a signer using the hex-encoded key from the
// DCLAW_EMERGENCY_KEY environment variable. It must be independently
// provisioned to prevent an OTA signing key from authorizing emergencies.
func NewEmergencySignerFromEnv() (*HMACSigner, error) {
	keyHex := os.Getenv("DCLAW_EMERGENCY_KEY")
	if keyHex == "" {
		return nil, errors.New("DCLAW_EMERGENCY_KEY is required for emergency signing")
	}
	key, err := decodeHex(keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid DCLAW_EMERGENCY_KEY: %w", err)
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

// NewHMACSignerFromKeyHex creates a signer from a hex-encoded key resolved
// from config.yaml. Falls back to the dedicated environment variable when empty.
func NewHMACSignerFromKeyHex(keyHex string) (*HMACSigner, error) {
	if keyHex == "" {
		return NewHMACSignerFromEnv()
	}
	key, err := decodeHex(keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid OTA HMAC key from config: %w", err)
	}
	return NewHMACSigner(key)
}

// NewEmergencySignerFromKeyHex creates an emergency signer from config,
// falling back only to the separate emergency environment variable.
func NewEmergencySignerFromKeyHex(keyHex string) (*HMACSigner, error) {
	if keyHex != "" {
		key, err := decodeHex(keyHex)
		if err != nil {
			return nil, fmt.Errorf("invalid emergency key from config: %w", err)
		}
		return NewHMACSigner(key)
	}
	return NewEmergencySignerFromEnv()
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
