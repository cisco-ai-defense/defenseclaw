// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// CredentialTransaction is the hook guardian's part in a per-user credential
// rotation (the standalone Linux/macOS lifecycle's rotate-credentials). The
// rotation writes it root-only next to the authorization ledger
// (managed.HookGuardianCredentialTransactionFile), under the reconcile lock,
// before it stages the next key, and changes or removes it only under that
// lock:
//
//   - prepare: the guardian renders every target from the staged key, but
//     only while the record names that key as next and the committed key as
//     previous. A staged key that no record names (the key files live in the
//     service account's data directory) is never rendered from.
//   - rollback: the guardian renders every target from the committed key
//     again, while the gateway still accepts the retiring key.
//   - commit: the rotation renames the staged key over the committed one and
//     removes the record.
//
// Every attestation a reconcile publishes while a record exists names its
// operation and phase (CredentialAttestation.OperationID and Phase), so the
// rotation never takes a reconcile from another phase or another operation
// as proof. The record holds no key material, only fingerprints
// (connector.UserScopedTokenKeyFingerprint).
type CredentialTransaction struct {
	Version     int    `json:"version"`
	OperationID string `json:"operation_id"`
	Phase       string `json:"phase"`
	StartedAt   string `json:"started_at"`
	// ManifestSHA256 is the roster (targets.yaml digest) the rotation
	// selected its targets from.
	ManifestSHA256 string `json:"manifest_sha256"`
	PreviousKeyID  string `json:"previous_key_id"`
	NextKeyID      string `json:"next_key_id"`
}

const (
	CredentialTransactionVersion  = 1
	CredentialTransactionMaxBytes = 64 << 10
)

// ParseCredentialTransaction strictly decodes and validates a record.
func ParseCredentialTransaction(data []byte) (CredentialTransaction, error) {
	var transaction CredentialTransaction
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&transaction); err != nil {
		return CredentialTransaction{}, fmt.Errorf("parse the guardian credential transaction: %w", err)
	}
	if decoder.Decode(new(json.RawMessage)) != io.EOF {
		return CredentialTransaction{}, errors.New("the guardian credential transaction has trailing content")
	}
	if transaction.Version != CredentialTransactionVersion ||
		!validTransactionRef(transaction.OperationID, transaction.Phase) || transaction.OperationID == "" ||
		!lowerHex(transaction.ManifestSHA256, 32) ||
		!lowerHex(transaction.PreviousKeyID, 32) || !lowerHex(transaction.NextKeyID, 32) ||
		transaction.PreviousKeyID == transaction.NextKeyID {
		return CredentialTransaction{}, errors.New("the guardian credential transaction has an invalid schema")
	}
	return transaction, nil
}

// RendersNext reports whether a guardian holding committedKeyID committed and
// stagedKeyID staged renders targets from the staged key.
func (t CredentialTransaction) RendersNext(committedKeyID, stagedKeyID string) bool {
	return t.Phase == CredentialPhasePrepare && committedKeyID == t.PreviousKeyID && stagedKeyID == t.NextKeyID
}
