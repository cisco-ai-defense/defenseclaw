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

package pipeline

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

// CorrelationKeyProjectionIntegritySigner is an immutable, process-local
// adapter from the redaction correlation key to audit projection integrity.
// The constructor snapshots both key material and identity; callers cannot
// rotate or mutate a live signer's custody tuple.
type CorrelationKeyProjectionIntegritySigner struct {
	key       [sha256.Size]byte
	keyID     string
	available bool
}

// NewCorrelationKeyProjectionIntegritySigner validates and snapshots one
// correlation key. A zero, unavailable, or internally inconsistent key fails
// closed with the bounded audit sentinel and never exposes key state.
func NewCorrelationKeyProjectionIntegritySigner(
	key redaction.CorrelationKey,
) (*CorrelationKeyProjectionIntegritySigner, error) {
	material, available := key.Material()
	if !available {
		return nil, audit.ErrIntegrityKeyUnavailable
	}

	digest := sha256.Sum256(material[:])
	expectedID := hex.EncodeToString(digest[:6])
	keyID := key.ID()
	if len(keyID) != len(expectedID) ||
		subtle.ConstantTimeCompare([]byte(keyID), []byte(expectedID)) != 1 {
		for index := range material {
			material[index] = 0
		}
		return nil, audit.ErrIntegrityKeyUnavailable
	}

	signer := &CorrelationKeyProjectionIntegritySigner{
		key:       material,
		keyID:     keyID,
		available: true,
	}
	for index := range material {
		material[index] = 0
	}
	return signer, nil
}

// KeyID returns the safe, stable identity of the snapshotted key. An
// unavailable or nil signer reports no identity.
func (signer *CorrelationKeyProjectionIntegritySigner) KeyID() string {
	if signer == nil || !signer.available {
		return ""
	}
	return signer.keyID
}

// HMACSHA256 authenticates the exact domain-separated message supplied by the
// audit writer. The signer deliberately adds no competing domain convention.
// It never retains or changes the caller's message.
func (signer *CorrelationKeyProjectionIntegritySigner) HMACSHA256(
	ctx context.Context,
	message []byte,
) ([]byte, error) {
	if signer == nil || !signer.available || signer.keyID == "" {
		return nil, audit.ErrIntegrityKeyUnavailable
	}
	if ctx == nil {
		return nil, errors.New("observability projection integrity context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	mac := hmac.New(sha256.New, signer.key[:])
	_, _ = mac.Write(message)
	signature := mac.Sum(nil)
	if err := ctx.Err(); err != nil {
		for index := range signature {
			signature[index] = 0
		}
		return nil, err
	}
	return signature, nil
}

var _ audit.ProjectionIntegritySigner = (*CorrelationKeyProjectionIntegritySigner)(nil)
