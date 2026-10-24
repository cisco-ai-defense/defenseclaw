// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// credentialBundleEnv is a managed test device whose bundle config names
// the credential ai-defense-api-key.
func credentialBundleEnv(t *testing.T) (*bundleCLIEnv, *enterprisebundle.Store) {
	t.Helper()
	e := newBundleCLIEnv(t)
	path := filepath.Join(e.in, "config.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := strings.Replace(string(raw), "enterprise:\n  profile: standalone\n", "enterprise:\n  profile: standalone\n  inspection:\n    ai_defense:\n      credential: ai-defense-api-key\n", 1)
	if cfg == string(raw) {
		t.Fatal("the test config has no enterprise profile line to extend")
	}
	writeBundleTestFile(t, path, []byte(cfg))
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	return e, bundleDevice(t, e)
}

// signCredentialBundle signs version of the test bundle with key (key id
// k1) and binds ai-defense-api-key to value.
func (e *bundleCLIEnv) signCredentialBundle(t *testing.T, version, value, key string) string {
	t.Helper()
	out := filepath.Join(e.dir, "v"+version+"-"+value+".dcbundle")
	if res, code := runBundle(t, e.signArgs("--out", out, "--key", key, "--key-id", "k1", "--version", version,
		"--secret-file", "ai-defense-api-key="+e.secretSource(t, value))...); code != 0 {
		t.Fatalf("sign exit %d:\n%s", code, res)
	}
	return out
}

// confirmSignedBundle records the bundle at path as the confirmed one, as an
// apply that converged does.
func confirmSignedBundle(t *testing.T, store *enterprisebundle.Store, path string) {
	t.Helper()
	b, err := readBundleInput(path)
	if err != nil {
		t.Fatal(err)
	}
	m, err := enterprisebundle.DecodeManifest(b.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	r, err := store.Receive(m.BundleID, m.Version, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Stage(r, b); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b.Manifest)
	digest := "sha256:" + strings.Repeat("5", 64)
	if err := store.Advance(r, enterprisebundle.StateVerified, func(r *enterprisebundle.Receipt) {
		r.SignerKeyID, r.ManifestSHA256, r.ExpectedDigest = "k1", hex.EncodeToString(sum[:]), digest
		r.SetDigestComparison(true, false, false)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Promote(r); err != nil {
		t.Fatal(err)
	}
	if err := store.Advance(r, enterprisebundle.StateApplied, func(r *enterprisebundle.Receipt) { r.EffectivePolicyDigest = digest }); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Confirm(r); err != nil {
		t.Fatal(err)
	}
}

// bundle sign binds every credential config.yaml references to the value
// --secret-file gives (value_sha256) and never writes the value; without a
// value it refuses secret_ref_unbound, and a malformed or repeated
// --secret-file is invalid arguments (GAP-0335).
func TestBundleSignBindsEveryCredentialValue(t *testing.T) {
	e, _ := credentialBundleEnv(t)
	key := filepath.Join(e.dir, "key.pem")
	out, code := runBundle(t, e.signArgs("--out", filepath.Join(e.dir, "unbound.dcbundle"), "--key", key, "--key-id", "k1")...)
	if code != bundleFailureExitCode() || !strings.Contains(out, `"code": "secret_ref_unbound"`) || !strings.Contains(out, "--secret-file ai-defense-api-key=") {
		t.Fatalf("sign without the value: exit %d\n%s", code, out)
	}
	signed := e.signCredentialBundle(t, "5", "key-1", key)
	b, err := readBundleInput(signed)
	if err != nil {
		t.Fatal(err)
	}
	m, err := enterprisebundle.DecodeManifest(b.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	want := enterprisebundle.CredentialValueSHA256("acme", "ai-defense-api-key", []byte("key-1"))
	if len(m.SecretRefs) != 1 || m.SecretRefs[0].ValueSHA256 != want {
		t.Fatalf("secret_refs %+v, want value_sha256 %s", m.SecretRefs, want)
	}
	raw, err := os.ReadFile(signed)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "key-1") {
		t.Fatal("the signed bundle carries the credential value")
	}
	for _, args := range [][]string{
		{"--secret-file", "ai-defense-api-key"},
		{"--secret-file", "Bad_Name=" + e.secretSource(t, "x")},
		{"--secret-file", "ai-defense-api-key=" + e.secretSource(t, "a"), "--secret-file", "ai-defense-api-key=" + e.secretSource(t, "b")},
		{"--secret-file", "ai-defense-api-key=" + filepath.Join(e.dir, "absent")},
	} {
		out, code := runBundle(t, e.signArgs(append([]string{"--out", filepath.Join(e.dir, "bad.dcbundle"), "--key", key, "--key-id", "k1"}, args...)...)...)
		if code != enterprisestatus.InvalidArgsExitCode(runtime.GOOS) {
			t.Fatalf("sign %v: exit %d, want invalid arguments\n%s", args, code, out)
		}
	}
	if out, code := runBundle(t, "sign", "--attach-sig", signed, "--in", signed, "--out", filepath.Join(e.dir, "x.dcbundle"), "--key-id", "k1",
		"--public-key", key, "--secret-file", "ai-defense-api-key="+e.secretSource(t, "c")); code != enterprisestatus.InvalidArgsExitCode(runtime.GOOS) {
		t.Fatalf("attach-sig with --secret-file: exit %d\n%s", code, out)
	}
}

// secret set stores a credential the confirmed bundle references only with
// the value that bundle signs. A new value needs a newer bundle that
// verifies on this device and signs it (--bundle); the confirmed bundle
// again, an older one, another value or an untrusted signer does not
// authorize it, and the refusal keeps the bundle's own reason. Before any
// bundle is confirmed nothing binds the credential (GAP-0335).
func TestSecretSetStoresOnlyAValueASignedBundleBinds(t *testing.T) {
	e, store := credentialBundleEnv(t)
	ctx := context.Background()
	key := filepath.Join(e.dir, "key.pem")
	v5 := e.signCredentialBundle(t, "5", "key-1", key)
	if err := checkSecretBinding(ctx, "ai-defense-api-key", []byte("any"), "", true); err != nil {
		t.Fatalf("no bundle confirmed: %v", err)
	}
	confirmSignedBundle(t, store, v5)
	v6 := e.signCredentialBundle(t, "6", "key-2", key)
	v4 := e.signCredentialBundle(t, "4", "key-2", key)
	_, other, _ := ed25519.GenerateKey(nil)
	der, _ := x509.MarshalPKCS8PrivateKey(other)
	otherKey := filepath.Join(e.dir, "other.pem")
	writeBundleTestFile(t, otherKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	untrusted := e.signCredentialBundle(t, "7", "key-2", otherKey)
	for _, tc := range []struct {
		name, value, bundle string
		want                enterprisebundle.Code
		reason              string
	}{
		{"the signed value", "key-1", "", "", ""},
		{"the signed value with a line ending", "key-1\n", "", "", ""},
		{"another value", "key-2", "", enterprisebundle.CodeSecretRefMismatch, "the confirmed policy bundle signs another value"},
		{"a credential the bundle does not reference", "key-9", "", "", ""},
		{"rotation to the value a newer bundle signs", "key-2", v6, "", ""},
		{"rotation to another value", "key-3", v6, enterprisebundle.CodeSecretRefMismatch, "the --bundle policy bundle signs another value"},
		{"the confirmed bundle as --bundle", "key-2", v5, enterprisebundle.CodeSecretRefMismatch, "signs another value"},
		{"an older bundle", "key-2", v4, enterprisebundle.CodeSecretRefMismatch, "version_not_newer"},
		{"an untrusted signer", "key-2", untrusted, enterprisebundle.CodeSecretRefMismatch, "signature_invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name := "ai-defense-api-key"
			if tc.name == "a credential the bundle does not reference" {
				name = "splunk-token"
			}
			err := checkSecretBinding(ctx, name, []byte(tc.value), tc.bundle, true)
			if enterprisebundle.CodeOf(err) != tc.want || (tc.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.reason)) {
				t.Fatalf("got %v, want %q naming %q", err, tc.want, tc.reason)
			}
			if err != nil && strings.Contains(err.Error(), tc.value) {
				t.Fatalf("the refusal prints the value: %v", err)
			}
		})
	}
}

// After an upgrade from a release whose bundles signed credential names
// only, the confirmed bundle binds no value: secret set refuses to change
// the credential (secret_ref_unbound). A rotation with a bundle that binds
// the new value is refused too while a value is stored (loop round 1,
// rc.7): a failed apply puts the old value back with secret set, which that
// bundle refuses, so the old config would keep the new credential. With
// nothing stored there is nothing to put back, and the bundle authorizes
// the value.
func TestSecretSetRefusesACredentialALegacyBundleSignsByNameOnly(t *testing.T) {
	e, store := credentialBundleEnv(t)
	key := filepath.Join(e.dir, "key.pem")
	bound := e.signCredentialBundle(t, "5", "key-1", key)
	b, err := readBundleInput(bound)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b.Manifest, &m); err != nil {
		t.Fatal(err)
	}
	for _, ref := range m["secret_refs"].([]any) {
		delete(ref.(map[string]any), "value_sha256")
	}
	if b.Manifest, err = json.MarshalIndent(m, "", "  "); err != nil {
		t.Fatal(err)
	}
	sig, err := enterprisebundle.Sign(b.Manifest, e.edKey, "k1")
	if err != nil {
		t.Fatal(err)
	}
	if b.Signature, err = sig.Marshal(); err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(e.dir, "legacy.dcbundle")
	if err := writeBundleArchive(legacy, b); err != nil {
		t.Fatal(err)
	}
	confirmSignedBundle(t, store, legacy)
	ctx := context.Background()
	if err := checkSecretBinding(ctx, "ai-defense-api-key", []byte("key-1"), "", true); enterprisebundle.CodeOf(err) != enterprisebundle.CodeSecretRefUnbound {
		t.Fatalf("legacy confirmed bundle: got %v, want secret_ref_unbound", err)
	}
	if code := secretBindingCode(checkSecretBinding(ctx, "ai-defense-api-key", []byte("key-1"), "", true)); code != "secret_ref_unbound" {
		t.Fatalf("errors[].code %q", code)
	}
	v6 := e.signCredentialBundle(t, "6", "key-2", key)
	err = checkSecretBinding(ctx, "ai-defense-api-key", []byte("key-2"), v6, true)
	if enterprisebundle.CodeOf(err) != enterprisebundle.CodeSecretRefUnbound || !strings.Contains(err.Error(), "could not put the stored value back") {
		t.Fatalf("rotation over a stored value: got %v, want secret_ref_unbound naming the put-back", err)
	}
	if strings.Contains(err.Error(), "key-2") {
		t.Fatalf("the refusal prints the value: %v", err)
	}
	if err := checkSecretBinding(ctx, "ai-defense-api-key", []byte("key-2"), v6, false); err != nil {
		t.Fatalf("rotation with nothing stored, with a bundle that binds the value: %v", err)
	}
}
