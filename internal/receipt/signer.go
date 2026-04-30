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

// Package receipt implements Ed25519-signed, hash-chained decision
// receipts for the DefenseClaw gateway. Each gateway decision (allow,
// deny, block, quarantine) can optionally produce a signed receipt
// that is independently verifiable offline.
//
// The receipt format conforms to draft-farley-acta-signed-receipts
// (https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/).
// Receipts produced by this package are cross-verifiable with:
//
//	npx @veritasacta/verify defenseclaw-receipts/*.json
//
// # Architecture
//
// The Signer is installed on the audit Logger via SetReceiptSigner.
// When an audit event flows through the Logger, the signer:
//
//  1. Constructs a Receipt from the event fields.
//  2. Computes the deterministic canonical JSON form of the signable payload.
//  3. Signs the canonical bytes with Ed25519.
//  4. Writes the signed receipt as a JSON file to the output directory.
//  5. Updates the chain hash for the next receipt.
//
// The signer is goroutine-safe. All state mutation is protected by
// a mutex. Receipt files are flushed synchronously to guarantee
// that a receipt is durable before the next event is processed.
package receipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Signer produces Ed25519-signed, hash-chained decision receipts.
// It is safe for concurrent use.
type Signer struct {
	mu         sync.Mutex
	privKey    ed25519.PrivateKey
	pubKeyHex  string
	outputDir  string
	prevHash   string // empty string = genesis
	seqCounter uint64
}

// NewSigner creates a receipt signer. If cfg.KeyPath is empty, an
// ephemeral Ed25519 key is generated (development only). The output
// directory is created if it does not exist.
func NewSigner(cfg Config) (*Signer, error) {
	outDir := cfg.OutputDir
	if outDir == "" {
		outDir = "./defenseclaw-receipts"
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("receipt: create output dir %s: %w", outDir, err)
	}

	var priv ed25519.PrivateKey
	if cfg.KeyPath != "" {
		raw, err := os.ReadFile(cfg.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("receipt: read key %s: %w", cfg.KeyPath, err)
		}
		seed, err := decodeSeed(raw)
		if err != nil {
			return nil, fmt.Errorf("receipt: parse key %s: %w", cfg.KeyPath, err)
		}
		priv = ed25519.NewKeyFromSeed(seed)
	} else {
		_, privGen, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("receipt: generate ephemeral key: %w", err)
		}
		priv = privGen
	}

	pub := priv.Public().(ed25519.PublicKey)
	return &Signer{
		privKey:   priv,
		pubKeyHex: hex.EncodeToString(pub),
		outputDir: outDir,
	}, nil
}

// SignEvent creates a signed receipt from a gateway decision event.
// The receipt is written to the output directory and the chain hash
// is updated for the next receipt. Returns the receipt and the
// receipt's SHA-256 hash (for stamping onto the audit event row).
func (s *Signer) SignEvent(toolName, decision, policyID, agentID, sessionID, reason string) (*Receipt, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rcpt := &Receipt{
		ReceiptID:           uuid.New().String(),
		ToolName:            toolName,
		Decision:            decision,
		PolicyID:            policyID,
		Timestamp:           time.Now().UTC(),
		PreviousReceiptHash: s.prevHash,
		AgentID:             agentID,
		SessionID:           sessionID,
		Reason:              reason,
	}

	// Compute the signable payload (all fields except signature and public_key).
	signable := signableMap(rcpt)
	canonical, err := jcs(signable)
	if err != nil {
		return nil, "", fmt.Errorf("receipt: canonicalize: %w", err)
	}

	// Sign with Ed25519.
	sig := ed25519.Sign(s.privKey, canonical)
	rcpt.Signature = hex.EncodeToString(sig)
	rcpt.PublicKey = s.pubKeyHex

	// Write the receipt to disk.
	filename := fmt.Sprintf("rcpt-%04d-%s.json", s.seqCounter, rcpt.ReceiptID[:8])
	path := filepath.Join(s.outputDir, filename)
	data, err := json.MarshalIndent(rcpt, "", "  ")
	if err != nil {
		return nil, "", fmt.Errorf("receipt: marshal: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return nil, "", fmt.Errorf("receipt: write %s: %w", path, err)
	}

	// Update chain hash for the next receipt.
	fullCanonical, err := jcs(fullMap(rcpt))
	if err != nil {
		return nil, "", fmt.Errorf("receipt: chain hash: %w", err)
	}
	hash := sha256.Sum256(fullCanonical)
	s.prevHash = "sha256:" + hex.EncodeToString(hash[:])
	s.seqCounter++

	return rcpt, s.prevHash, nil
}

// PublicKeyHex returns the hex-encoded Ed25519 public key.
func (s *Signer) PublicKeyHex() string {
	return s.pubKeyHex
}

// ---- Receipt canonicalization ----

// jcs produces deterministic canonical JSON for the DefenseClaw receipt
// schema subset by sorting object keys lexicographically at every nesting
// depth and using encoding/json for primitive values. It is intentionally
// scoped to the flat receipt payloads emitted by this package rather than
// claiming a complete RFC 8785 implementation for arbitrary JSON values.
func jcs(v interface{}) ([]byte, error) {
	switch val := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		var buf strings.Builder
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			keyJSON, _ := json.Marshal(k)
			buf.Write(keyJSON)
			buf.WriteByte(':')
			childBytes, err := jcs(val[k])
			if err != nil {
				return nil, err
			}
			buf.Write(childBytes)
		}
		buf.WriteByte('}')
		return []byte(buf.String()), nil
	default:
		return json.Marshal(v)
	}
}

// signableMap produces the map used for signature computation.
// Excludes signature and public_key fields.
func signableMap(r *Receipt) map[string]interface{} {
	m := make(map[string]interface{})
	m["receipt_id"] = r.ReceiptID
	m["tool_name"] = r.ToolName
	m["decision"] = r.Decision
	m["policy_id"] = r.PolicyID
	m["timestamp"] = r.Timestamp.Format(time.RFC3339Nano)
	m["previous_receipt_hash"] = r.PreviousReceiptHash
	if r.PolicyDigest != "" {
		m["policy_digest"] = r.PolicyDigest
	}
	if r.AgentID != "" {
		m["agent_id"] = r.AgentID
	}
	if r.SessionID != "" {
		m["session_id"] = r.SessionID
	}
	if r.Reason != "" {
		m["reason"] = r.Reason
	}
	return m
}

// fullMap includes all fields (for chain hash computation).
func fullMap(r *Receipt) map[string]interface{} {
	m := signableMap(r)
	m["signature"] = r.Signature
	m["public_key"] = r.PublicKey
	return m
}

// decodeSeed extracts the 32-byte Ed25519 seed from one of the persisted
// key formats documented for receipts.key_path: a raw 32-byte seed, a
// 64-character hex seed, or Go's 64-byte ed25519 private key format
// (seed || public key).
func decodeSeed(raw []byte) ([]byte, error) {
	s := strings.TrimSpace(string(raw))

	// Try hex-encoded 32-byte seed (64 hex chars).
	if len(s) == 64 {
		seed, err := hex.DecodeString(s)
		if err == nil && len(seed) == 32 {
			return seed, nil
		}
	}

	// Try raw 32 bytes.
	if len(raw) == 32 {
		return raw, nil
	}

	// Try 64 bytes (Go's ed25519 private key format = seed + public).
	if len(raw) == 64 {
		return raw[:32], nil
	}

	return nil, fmt.Errorf("unsupported key format (expected raw 32-byte seed, 64-character hex seed, or 64-byte Go ed25519 private key; got %d bytes)", len(raw))
}
