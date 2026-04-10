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
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// GenerateKeyPair creates a new Ed25519 key pair.
func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("signing: generate key pair: %w", err)
	}
	return pub, priv, nil
}

// Fingerprint returns the SHA-256 hex digest of a public key.
func Fingerprint(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:])
}

// Sign computes the manifest hash for dirPath, signs it with privateKey,
// and writes .defenseclaw-sig.json into dirPath.
func Sign(dirPath string, privateKey ed25519.PrivateKey, publisher string) (*Signature, error) {
	contentHash, err := HashDirectory(dirPath)
	if err != nil {
		return nil, err
	}

	hashBytes, err := hex.DecodeString(contentHash)
	if err != nil {
		return nil, fmt.Errorf("signing: decode content hash: %w", err)
	}

	sig := ed25519.Sign(privateKey, hashBytes)
	pub := privateKey.Public().(ed25519.PublicKey)

	s := &Signature{
		Version:     SignatureVersion,
		Algorithm:   AlgorithmEd25519,
		Publisher:   publisher,
		PublicKey:   hex.EncodeToString(pub),
		Fingerprint: Fingerprint(pub),
		SignedAt:    time.Now().UTC().Format(time.RFC3339),
		ContentHash: contentHash,
		Sig:         hex.EncodeToString(sig),
	}

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("signing: marshal signature: %w", err)
	}
	data = append(data, '\n')

	sigPath := filepath.Join(dirPath, SignatureFileName)
	if err := os.WriteFile(sigPath, data, 0644); err != nil {
		return nil, fmt.Errorf("signing: write %s: %w", sigPath, err)
	}

	return s, nil
}

// ReadSignature reads and parses .defenseclaw-sig.json from dirPath.
func ReadSignature(dirPath string) (*Signature, error) {
	sigPath := filepath.Join(dirPath, SignatureFileName)
	data, err := os.ReadFile(sigPath)
	if err != nil {
		return nil, err
	}
	var sig Signature
	if err := json.Unmarshal(data, &sig); err != nil {
		return nil, fmt.Errorf("signing: parse %s: %w", sigPath, err)
	}
	return &sig, nil
}

// Verify checks the signature in dirPath against the provided trusted publishers.
// It re-computes the manifest hash, validates the Ed25519 signature, and checks
// whether the signing key is in the trust set.
func Verify(dirPath string, trustedKeys []Publisher) (*VerifyResult, error) {
	sig, err := ReadSignature(dirPath)
	if err != nil {
		if os.IsNotExist(err) {
			return &VerifyResult{
				Signed:   false,
				Verified: false,
				Trusted:  false,
				Reason:   "no signature file found",
			}, nil
		}
		return nil, fmt.Errorf("signing: read signature: %w", err)
	}

	if sig.Version != SignatureVersion {
		return &VerifyResult{
			Signed: true,
			Reason: fmt.Sprintf("unsupported signature version %d", sig.Version),
		}, nil
	}
	if sig.Algorithm != AlgorithmEd25519 {
		return &VerifyResult{
			Signed: true,
			Reason: fmt.Sprintf("unsupported algorithm %q", sig.Algorithm),
		}, nil
	}

	pubKeyBytes, err := hex.DecodeString(sig.PublicKey)
	if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
		return &VerifyResult{
			Signed: true,
			Reason: "invalid public key in signature file",
		}, nil
	}
	pub := ed25519.PublicKey(pubKeyBytes)

	actualFP := Fingerprint(pub)
	if actualFP != sig.Fingerprint {
		return &VerifyResult{
			Signed: true,
			Reason: "fingerprint mismatch in signature file",
		}, nil
	}

	contentHash, err := HashDirectory(dirPath)
	if err != nil {
		return nil, err
	}
	if contentHash != sig.ContentHash {
		return &VerifyResult{
			Signed:      true,
			Publisher:   sig.Publisher,
			Fingerprint: sig.Fingerprint,
			Reason:      "content has been modified since signing",
		}, nil
	}

	hashBytes, err := hex.DecodeString(contentHash)
	if err != nil {
		return nil, fmt.Errorf("signing: decode content hash: %w", err)
	}

	sigBytes, err := hex.DecodeString(sig.Sig)
	if err != nil {
		return &VerifyResult{
			Signed: true,
			Reason: "invalid signature encoding",
		}, nil
	}

	if !ed25519.Verify(pub, hashBytes, sigBytes) {
		return &VerifyResult{
			Signed:      true,
			Publisher:   sig.Publisher,
			Fingerprint: sig.Fingerprint,
			Reason:      "signature verification failed",
		}, nil
	}

	trusted := false
	for _, tk := range trustedKeys {
		if tk.Fingerprint == sig.Fingerprint {
			trusted = true
			break
		}
	}

	reason := "signature valid"
	if !trusted {
		reason = "signature valid but publisher is not trusted"
	}

	return &VerifyResult{
		Verified:    trusted,
		Signed:      true,
		Trusted:     trusted,
		Publisher:   sig.Publisher,
		Fingerprint: sig.Fingerprint,
		Reason:      reason,
	}, nil
}
