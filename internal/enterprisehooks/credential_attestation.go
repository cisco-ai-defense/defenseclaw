// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// CredentialAttestation is what the standalone Unix guardian's last
// reconcile did to each target the manifest enables, and which per-user
// credential key it rendered from. It is current evidence only: the
// authorization ledger carries a target's last success forward (so a user
// cannot unenroll by breaking their own home), while a row here says what
// that one run left behind. rotate-credentials reads it to prove that every
// user moved to a new key before it commits the key. The guardian writes it
// root-only next to the ledger (managed.HookGuardianCredentialAttestationFile).
type CredentialAttestation struct {
	Version int `json:"version"`
	// ID is random per reconcile, so a reader can tell a new run from the
	// one it read before.
	ID             string `json:"id"`
	UpdatedAt      string `json:"updated_at"`
	ManifestSHA256 string `json:"manifest_sha256"`
	// KeyID is the fingerprint (connector.UserScopedTokenKeyFingerprint) of
	// the key the run derived per-user credentials from; empty when there
	// is none yet.
	KeyID   string                        `json:"key_id,omitempty"`
	Targets []CredentialAttestationTarget `json:"targets"`
}

// CredentialAttestationTarget is one enabled manifest target.
type CredentialAttestationTarget struct {
	Connector string `json:"connector"`
	User      string `json:"user,omitempty"`
	UserHome  string `json:"user_home,omitempty"`
	// UID is the account the run resolved; -1 when it resolved none.
	UID   int    `json:"uid"`
	State string `json:"state"`
	// Credentials: the target's hooks carry per-user credentials derived
	// from KeyID (a machine-policy row, for example, carries none).
	Credentials bool `json:"credentials,omitempty"`
	// Verified: the run re-read the target's installed hooks and found them
	// rendered with those credentials, without repairing anything.
	Verified bool `json:"verified,omitempty"`
}

// Target states of a credential attestation row.
const (
	CredentialTargetCurrent = "current"
	CredentialTargetPending = "pending"
	CredentialTargetFailed  = "failed"
)

const (
	CredentialAttestationVersion = 1
	// CredentialAttestationMaxBytes bounds the record like the ledger.
	CredentialAttestationMaxBytes = 4 << 20
)

// ParseCredentialAttestation strictly decodes and validates a record.
func ParseCredentialAttestation(data []byte) (CredentialAttestation, error) {
	var attestation CredentialAttestation
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&attestation); err != nil {
		return CredentialAttestation{}, fmt.Errorf("parse the guardian credential attestation: %w", err)
	}
	if decoder.Decode(new(json.RawMessage)) != io.EOF {
		return CredentialAttestation{}, errors.New("the guardian credential attestation has trailing content")
	}
	if attestation.Version != CredentialAttestationVersion ||
		!lowerHex(attestation.ID, 16) || !lowerHex(attestation.ManifestSHA256, 32) ||
		(attestation.KeyID != "" && !lowerHex(attestation.KeyID, 32)) || attestation.Targets == nil {
		return CredentialAttestation{}, errors.New("the guardian credential attestation has an invalid schema")
	}
	seen := make(map[string]bool, len(attestation.Targets))
	for _, target := range attestation.Targets {
		key := target.Key()
		switch {
		case strings.TrimSpace(target.Connector) == "" || (target.User == "" && target.UserHome == ""):
			return CredentialAttestation{}, errors.New("the guardian credential attestation has an incomplete target")
		case target.State != CredentialTargetCurrent && target.State != CredentialTargetPending && target.State != CredentialTargetFailed:
			return CredentialAttestation{}, fmt.Errorf("the guardian credential attestation has target state %q", target.State)
		case (target.Credentials || target.Verified) && target.State != CredentialTargetCurrent,
			target.Verified && !target.Credentials,
			target.Credentials && (target.UID < 0 || attestation.KeyID == ""):
			return CredentialAttestation{}, errors.New("the guardian credential attestation has an inconsistent target")
		case seen[key]:
			return CredentialAttestation{}, fmt.Errorf("the guardian credential attestation lists %s twice", target.Label())
		}
		seen[key] = true
	}
	return attestation, nil
}

// Key identifies the target within one attestation.
func (t CredentialAttestationTarget) Key() string {
	return strings.ToLower(strings.TrimSpace(t.Connector)) + "\x00" + t.User + "\x00" + t.UserHome
}

// Label names the target for an administrator.
func (t CredentialAttestationTarget) Label() string {
	who := t.User
	if who == "" {
		who = t.UserHome
	}
	return t.Connector + " for user " + who
}

func lowerHex(value string, byteLength int) bool {
	if len(value) != byteLength*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
