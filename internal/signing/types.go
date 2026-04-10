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

import "time"

const (
	SignatureFileName = ".defenseclaw-sig.json"
	SignatureVersion  = 1
	AlgorithmEd25519 = "ed25519"
)

// Signature is the on-disk representation stored in .defenseclaw-sig.json.
type Signature struct {
	Version     int    `json:"version"`
	Algorithm   string `json:"algorithm"`
	Publisher   string `json:"publisher"`
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
	SignedAt    string `json:"signed_at"`
	ContentHash string `json:"content_hash"`
	Sig         string `json:"signature"`
}

// Publisher represents a trusted publisher in the trust store.
type Publisher struct {
	Name        string `json:"name"        yaml:"name"`
	PublicKey   string `json:"public_key"  yaml:"public_key"`
	Fingerprint string `json:"fingerprint" yaml:"fingerprint"`
	AddedAt     string `json:"added_at"    yaml:"added_at"`
}

// VerifyResult is returned by Verify with the outcome of signature validation.
type VerifyResult struct {
	Verified    bool   `json:"verified"`
	Signed      bool   `json:"signed"`
	Trusted     bool   `json:"trusted"`
	Publisher   string `json:"publisher,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Reason      string `json:"reason"`
}

// SignatureEntry is the DB-level record for a verified (or failed) signature.
type SignatureEntry struct {
	ID          string    `json:"id"`
	TargetType  string    `json:"target_type"`
	TargetName  string    `json:"target_name"`
	Publisher   string    `json:"publisher"`
	Fingerprint string    `json:"fingerprint"`
	Verified    bool      `json:"verified"`
	VerifiedAt  time.Time `json:"verified_at"`
	ContentHash string    `json:"content_hash"`
	Reason      string    `json:"reason"`
}
