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

package signing

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

const publishersFile = "publishers.yaml"

// TrustStore manages the set of trusted publisher public keys.
type TrustStore struct {
	dir        string
	mu         sync.RWMutex
	publishers []Publisher
}

// NewTrustStore creates a TrustStore backed by the given directory.
func NewTrustStore(dir string) *TrustStore {
	return &TrustStore{dir: dir}
}

// Load reads publishers.yaml from disk.
func (ts *TrustStore) Load() error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	path := filepath.Join(ts.dir, publishersFile)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			ts.publishers = nil
			return nil
		}
		return fmt.Errorf("signing: read trust store: %w", err)
	}

	var pubs []Publisher
	if err := yaml.Unmarshal(data, &pubs); err != nil {
		return fmt.Errorf("signing: parse trust store: %w", err)
	}
	ts.publishers = pubs
	return nil
}

// Save writes the current publishers list to publishers.yaml.
func (ts *TrustStore) Save() error {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	if err := os.MkdirAll(ts.dir, 0755); err != nil {
		return fmt.Errorf("signing: create trust dir: %w", err)
	}

	data, err := yaml.Marshal(ts.publishers)
	if err != nil {
		return fmt.Errorf("signing: marshal trust store: %w", err)
	}

	path := filepath.Join(ts.dir, publishersFile)
	return os.WriteFile(path, data, 0644)
}

// Add registers a new trusted publisher. pubKeyHex is the hex-encoded Ed25519
// public key. Returns an error if the fingerprint is already trusted.
func (ts *TrustStore) Add(name, pubKeyHex string) (Publisher, error) {
	keyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil || len(keyBytes) != ed25519.PublicKeySize {
		return Publisher{}, fmt.Errorf("signing: invalid Ed25519 public key (expected %d bytes)", ed25519.PublicKeySize)
	}

	fp := sha256Hex(keyBytes)

	ts.mu.Lock()
	defer ts.mu.Unlock()

	for _, p := range ts.publishers {
		if p.Fingerprint == fp {
			return Publisher{}, fmt.Errorf("signing: publisher with fingerprint %s already trusted", fp)
		}
	}

	pub := Publisher{
		Name:        name,
		PublicKey:   pubKeyHex,
		Fingerprint: fp,
		AddedAt:     time.Now().UTC().Format(time.RFC3339),
	}
	ts.publishers = append(ts.publishers, pub)
	return pub, nil
}

// Remove deletes a publisher by fingerprint.
func (ts *TrustStore) Remove(fingerprint string) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	for i, p := range ts.publishers {
		if p.Fingerprint == fingerprint {
			ts.publishers = append(ts.publishers[:i], ts.publishers[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("signing: fingerprint %s not found in trust store", fingerprint)
}

// List returns a copy of the trusted publishers.
func (ts *TrustStore) List() []Publisher {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	out := make([]Publisher, len(ts.publishers))
	copy(out, ts.publishers)
	return out
}

// IsTrusted checks whether a fingerprint is in the trust store.
func (ts *TrustStore) IsTrusted(fingerprint string) bool {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	for _, p := range ts.publishers {
		if p.Fingerprint == fingerprint {
			return true
		}
	}
	return false
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
