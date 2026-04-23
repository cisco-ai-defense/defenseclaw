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

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestNewSigner_EphemeralKey(t *testing.T) {
	dir := t.TempDir()
	s, err := NewSigner(Config{OutputDir: dir})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	if s.PublicKeyHex() == "" {
		t.Fatal("expected non-empty public key")
	}
	if len(s.pubKeyHex) != 64 {
		t.Fatalf("expected 64-char hex public key, got %d chars", len(s.pubKeyHex))
	}
}

func TestSignEvent_ProducesValidReceipt(t *testing.T) {
	dir := t.TempDir()
	s, err := NewSigner(Config{OutputDir: dir})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	rcpt, _, err := s.SignEvent("claw:write_file", "deny", "policy-prod", "agent-1", "sess-1", "malicious content detected")
	if err != nil {
		t.Fatalf("SignEvent: %v", err)
	}

	if rcpt.ReceiptID == "" {
		t.Error("expected non-empty receipt_id")
	}
	if rcpt.ToolName != "claw:write_file" {
		t.Errorf("tool_name = %q, want %q", rcpt.ToolName, "claw:write_file")
	}
	if rcpt.Decision != "deny" {
		t.Errorf("decision = %q, want %q", rcpt.Decision, "deny")
	}
	if rcpt.PreviousReceiptHash != "" {
		t.Errorf("genesis receipt should have empty previous_receipt_hash, got %q", rcpt.PreviousReceiptHash)
	}
	if rcpt.Signature == "" {
		t.Error("expected non-empty signature")
	}
	if rcpt.PublicKey == "" {
		t.Error("expected non-empty public_key")
	}
}

func TestSignEvent_SignatureVerifies(t *testing.T) {
	dir := t.TempDir()
	s, err := NewSigner(Config{OutputDir: dir})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	rcpt, _, err := s.SignEvent("claw:exec", "allow", "policy-dev", "", "", "")
	if err != nil {
		t.Fatalf("SignEvent: %v", err)
	}

	// Reconstruct the signable payload and verify the signature.
	signable := signableMap(rcpt)
	canonical, err := jcs(signable)
	if err != nil {
		t.Fatalf("jcs: %v", err)
	}

	sigBytes, err := hex.DecodeString(rcpt.Signature)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	pubBytes, err := hex.DecodeString(rcpt.PublicKey)
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}

	if !ed25519.Verify(pubBytes, canonical, sigBytes) {
		t.Error("signature verification failed")
	}
}

func TestSignEvent_ChainIntegrity(t *testing.T) {
	dir := t.TempDir()
	s, err := NewSigner(Config{OutputDir: dir})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	r1, _, err := s.SignEvent("tool:a", "allow", "p1", "", "", "")
	if err != nil {
		t.Fatalf("SignEvent r1: %v", err)
	}
	r2, _, err := s.SignEvent("tool:b", "deny", "p1", "", "", "")
	if err != nil {
		t.Fatalf("SignEvent r2: %v", err)
	}
	r3, _, err := s.SignEvent("tool:c", "allow", "p1", "", "", "")
	if err != nil {
		t.Fatalf("SignEvent r3: %v", err)
	}

	// r1 is genesis: no previous hash.
	if r1.PreviousReceiptHash != "" {
		t.Errorf("r1 (genesis) should have empty previous_receipt_hash")
	}

	// r2 should chain to r1.
	r1Full := fullMap(r1)
	r1Canonical, _ := jcs(r1Full)
	r1Hash := sha256.Sum256(r1Canonical)
	expectedR2Prev := "sha256:" + hex.EncodeToString(r1Hash[:])
	if r2.PreviousReceiptHash != expectedR2Prev {
		t.Errorf("r2.previous_receipt_hash = %q, want %q", r2.PreviousReceiptHash, expectedR2Prev)
	}

	// r3 should chain to r2.
	r2Full := fullMap(r2)
	r2Canonical, _ := jcs(r2Full)
	r2Hash := sha256.Sum256(r2Canonical)
	expectedR3Prev := "sha256:" + hex.EncodeToString(r2Hash[:])
	if r3.PreviousReceiptHash != expectedR3Prev {
		t.Errorf("r3.previous_receipt_hash = %q, want %q", r3.PreviousReceiptHash, expectedR3Prev)
	}
}

func TestSignEvent_WritesFiles(t *testing.T) {
	dir := t.TempDir()
	s, err := NewSigner(Config{OutputDir: dir})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	for i := 0; i < 3; i++ {
		if _, _, err := s.SignEvent("tool:test", "allow", "p", "", "", ""); err != nil {
			t.Fatalf("SignEvent %d: %v", i, err)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 receipt files, got %d", len(entries))
	}

	// Verify each file is valid JSON with expected fields.
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatalf("ReadFile %s: %v", entry.Name(), err)
		}
		var rcpt Receipt
		if err := json.Unmarshal(data, &rcpt); err != nil {
			t.Fatalf("Unmarshal %s: %v", entry.Name(), err)
		}
		if rcpt.ReceiptID == "" {
			t.Errorf("%s: empty receipt_id", entry.Name())
		}
		if rcpt.Signature == "" {
			t.Errorf("%s: empty signature", entry.Name())
		}
	}
}

func TestSignEvent_TamperDetection(t *testing.T) {
	dir := t.TempDir()
	s, err := NewSigner(Config{OutputDir: dir})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	rcpt, _, err := s.SignEvent("tool:x", "deny", "p1", "", "", "blocked")
	if err != nil {
		t.Fatalf("SignEvent: %v", err)
	}

	// Tamper with the decision field.
	tampered := *rcpt
	tampered.Decision = "allow"

	// Re-verify: signature should fail on the tampered receipt.
	signable := signableMap(&tampered)
	canonical, _ := jcs(signable)
	sigBytes, _ := hex.DecodeString(tampered.Signature)
	pubBytes, _ := hex.DecodeString(tampered.PublicKey)

	if ed25519.Verify(pubBytes, canonical, sigBytes) {
		t.Error("tampered receipt should fail signature verification")
	}
}

func TestJCS_Deterministic(t *testing.T) {
	m := map[string]interface{}{
		"z_field": "last",
		"a_field": "first",
		"m_field": "middle",
	}
	b1, _ := jcs(m)
	b2, _ := jcs(m)

	if string(b1) != string(b2) {
		t.Error("JCS should produce deterministic output")
	}

	// Keys must be in lexicographic order.
	expected := `{"a_field":"first","m_field":"middle","z_field":"last"}`
	if string(b1) != expected {
		t.Errorf("JCS output = %s, want %s", string(b1), expected)
	}
}

func TestSignEvent_ConcurrentSafety(t *testing.T) {
	dir := t.TempDir()
	s, err := NewSigner(Config{OutputDir: dir})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	errs := make(chan error, 50)
	for i := 0; i < 50; i++ {
		go func(i int) {
			_, _, err := s.SignEvent("tool:concurrent", "allow", "p", "", "", "")
			errs <- err
		}(i)
	}

	for i := 0; i < 50; i++ {
		if err := <-errs; err != nil {
			t.Errorf("concurrent SignEvent %d: %v", i, err)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 50 {
		t.Errorf("expected 50 receipt files, got %d", len(entries))
	}
}
