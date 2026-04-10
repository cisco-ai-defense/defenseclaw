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
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func setupSkillDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "skill.yaml"), []byte("name: test-skill\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.py"), []byte("print('hello')\n"), 0644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	dir := setupSkillDir(t)
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	sig, err := Sign(dir, priv, "test-publisher")
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if sig.Publisher != "test-publisher" {
		t.Errorf("publisher = %q, want %q", sig.Publisher, "test-publisher")
	}
	if sig.Algorithm != AlgorithmEd25519 {
		t.Errorf("algorithm = %q, want %q", sig.Algorithm, AlgorithmEd25519)
	}

	trusted := []Publisher{{
		Name:        "test-publisher",
		PublicKey:   hex.EncodeToString(pub),
		Fingerprint: Fingerprint(pub),
	}}
	result, err := Verify(dir, trusted)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !result.Verified {
		t.Errorf("expected verified=true, got false: %s", result.Reason)
	}
	if !result.Signed {
		t.Error("expected signed=true")
	}
	if !result.Trusted {
		t.Error("expected trusted=true")
	}
}

func TestVerifyDetectsTamperedContent(t *testing.T) {
	dir := setupSkillDir(t)
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Sign(dir, priv, "publisher"); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "main.py"), []byte("print('tampered')\n"), 0644); err != nil {
		t.Fatal(err)
	}

	trusted := []Publisher{{
		Name:        "publisher",
		PublicKey:   hex.EncodeToString(pub),
		Fingerprint: Fingerprint(pub),
	}}
	result, err := Verify(dir, trusted)
	if err != nil {
		t.Fatal(err)
	}
	if result.Verified {
		t.Error("expected verified=false for tampered content")
	}
	if result.Reason != "content has been modified since signing" {
		t.Errorf("unexpected reason: %s", result.Reason)
	}
}

func TestVerifyRejectsUntrustedPublisher(t *testing.T) {
	dir := setupSkillDir(t)
	_, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Sign(dir, priv, "unknown"); err != nil {
		t.Fatal(err)
	}

	otherPub, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	trusted := []Publisher{{
		Name:        "other",
		PublicKey:   hex.EncodeToString(otherPub),
		Fingerprint: Fingerprint(otherPub),
	}}
	result, err := Verify(dir, trusted)
	if err != nil {
		t.Fatal(err)
	}
	if result.Verified {
		t.Error("expected verified=false for untrusted publisher")
	}
	if result.Trusted {
		t.Error("expected trusted=false")
	}
	if !result.Signed {
		t.Error("expected signed=true")
	}
}

func TestVerifyNoSignatureFile(t *testing.T) {
	dir := setupSkillDir(t)
	result, err := Verify(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Signed {
		t.Error("expected signed=false when no sig file")
	}
	if result.Verified {
		t.Error("expected verified=false when no sig file")
	}
}

func TestManifestHashDeterminism(t *testing.T) {
	dir := setupSkillDir(t)
	h1, err := HashDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := HashDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Errorf("manifest hash not deterministic: %s != %s", h1, h2)
	}
}

func TestManifestHashExcludesSigFile(t *testing.T) {
	dir := setupSkillDir(t)
	h1, err := HashDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}

	_, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Sign(dir, priv, "pub"); err != nil {
		t.Fatal(err)
	}

	h2, err := HashDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Errorf("manifest hash changed after signing: %s != %s", h1, h2)
	}
}

func TestTrustStoreAddListRemove(t *testing.T) {
	dir := t.TempDir()
	ts := NewTrustStore(dir)

	pub, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pubHex := hex.EncodeToString(pub)
	fp := Fingerprint(pub)

	p, err := ts.Add("cisco", pubHex)
	if err != nil {
		t.Fatal(err)
	}
	if p.Fingerprint != fp {
		t.Errorf("fingerprint = %q, want %q", p.Fingerprint, fp)
	}

	if err := ts.Save(); err != nil {
		t.Fatal(err)
	}

	ts2 := NewTrustStore(dir)
	if err := ts2.Load(); err != nil {
		t.Fatal(err)
	}
	list := ts2.List()
	if len(list) != 1 {
		t.Fatalf("expected 1 publisher, got %d", len(list))
	}
	if list[0].Name != "cisco" {
		t.Errorf("name = %q, want %q", list[0].Name, "cisco")
	}
	if !ts2.IsTrusted(fp) {
		t.Error("expected IsTrusted=true")
	}

	if err := ts2.Remove(fp); err != nil {
		t.Fatal(err)
	}
	if ts2.IsTrusted(fp) {
		t.Error("expected IsTrusted=false after remove")
	}
}

func TestTrustStoreRejectsDuplicate(t *testing.T) {
	ts := NewTrustStore(t.TempDir())
	pub, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pubHex := hex.EncodeToString(pub)

	if _, err := ts.Add("first", pubHex); err != nil {
		t.Fatal(err)
	}
	if _, err := ts.Add("second", pubHex); err == nil {
		t.Error("expected error adding duplicate key")
	}
}

func TestTrustStoreRejectsInvalidKey(t *testing.T) {
	ts := NewTrustStore(t.TempDir())
	if _, err := ts.Add("bad", "not-hex"); err == nil {
		t.Error("expected error for invalid hex")
	}
	if _, err := ts.Add("bad", hex.EncodeToString([]byte("tooshort"))); err == nil {
		t.Error("expected error for wrong key length")
	}
}

func TestFingerprintConsistency(t *testing.T) {
	pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	fp1 := Fingerprint(pub)
	fp2 := Fingerprint(pub)
	if fp1 != fp2 {
		t.Errorf("fingerprint not consistent: %s != %s", fp1, fp2)
	}
}
