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

package receipt

import "time"

// Receipt is a signed, hash-chained decision record conforming to
// draft-farley-acta-signed-receipts. Each receipt captures one
// gateway decision (allow, deny, block, quarantine) and is
// cryptographically linked to the previous receipt in the chain.
//
// Receipts are designed for offline verification: any verifier with
// the chain can reconstruct the hashes and confirm that no receipt
// has been tampered with, inserted, deleted, or reordered.
//
// Format reference: https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/
type Receipt struct {
	// ReceiptID is a unique identifier for this receipt (UUID v4).
	ReceiptID string `json:"receipt_id"`

	// ToolName is the tool or resource the decision applies to
	// (e.g., "claw:write_file", "mcp:fetch", "skill:code-review").
	ToolName string `json:"tool_name"`

	// Decision is the gateway verdict: "allow", "deny", "block",
	// "quarantine", or "disable".
	Decision string `json:"decision"`

	// PolicyID identifies the policy bundle that produced the decision.
	PolicyID string `json:"policy_id"`

	// PolicyDigest is the SHA-256 hash of the policy content at
	// evaluation time. Proves which exact policy version was active.
	PolicyDigest string `json:"policy_digest,omitempty"`

	// Timestamp is the UTC time the decision was made.
	Timestamp time.Time `json:"timestamp"`

	// PreviousReceiptHash is the SHA-256 hash of the previous
	// receipt's JCS-canonical form. Null for the first receipt in
	// a chain (the genesis receipt).
	PreviousReceiptHash string `json:"previous_receipt_hash"`

	// AgentID identifies the agent that triggered the decision.
	AgentID string `json:"agent_id,omitempty"`

	// SessionID ties the receipt to a specific agent session.
	SessionID string `json:"session_id,omitempty"`

	// Reason is a short human-readable explanation of why the
	// decision was made (e.g., scanner finding, policy rule).
	Reason string `json:"reason,omitempty"`

	// Signature is the Ed25519 signature over the JCS-canonical
	// form of the receipt (excluding the signature and public_key
	// fields themselves).
	Signature string `json:"signature"`

	// PublicKey is the hex-encoded Ed25519 public key that produced
	// the signature. Verifiers use this to check the signature
	// without requiring a key registry.
	PublicKey string `json:"public_key"`
}

// Config controls receipt signing behavior for the gateway.
type Config struct {
	// Enabled turns receipt signing on. Default: false.
	Enabled bool `json:"enabled" yaml:"enabled"`

	// OutputDir is the directory where receipt JSON files are written.
	// Default: "./defenseclaw-receipts".
	OutputDir string `json:"output_dir" yaml:"output_dir"`

	// KeyPath is the path to an Ed25519 signing seed. Supported
	// formats are a raw 32-byte seed, a 64-character hex seed, or
	// a 64-byte Go ed25519 private key (seed || public key). If
	// empty, a new ephemeral key is generated on startup (suitable
	// for development; not recommended for production).
	KeyPath string `json:"key_path" yaml:"key_path"`
}
