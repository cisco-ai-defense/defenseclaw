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

// Loop round 2 (rc.7), finding 1: the Windows wrapper read any refusal of a
// put-back (credential_in_use, secret_ref_mismatch) as proof the delivered
// bundle was confirmed and dropped its journal, so a failed apply over an
// old config that references a credential with no value stored kept the
// new value. The put-back now carries the bundle confirmed before the
// rotation (--undo-rotation): it runs while that bundle is still confirmed
// and does not sign the value stored now, and only rotation_confirmed says
// the rotation committed. A rotation runs only while the journaled bundle is
// confirmed (--if-confirmed).
func TestSecretTransactionPutsBackOnlyWhileTheRotationIsUnconfirmed(t *testing.T) {
	e, store := credentialBundleEnv(t)
	key := filepath.Join(e.dir, "key.pem")
	const name = "ai-defense-api-key"
	manifestSHA := func(path string) string {
		b, err := readBundleInput(path)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b.Manifest)
		return hex.EncodeToString(sum[:])
	}
	check := func(opts enterpriseSecretOptions, stored string, storedOK bool) enterprisebundle.Code {
		t.Helper()
		if opts.undoRotation != "" && opts.ifStored == "" {
			sum := sha256.Sum256([]byte(stored))
			opts.ifStored = hex.EncodeToString(sum[:])
		}
		err := checkSecretTransaction(name, &opts, []byte(stored), storedOK)
		if err == nil {
			return ""
		}
		if strings.Contains(err.Error(), "key-") {
			t.Fatalf("the refusal prints the value: %v", err)
		}
		return enterprisebundle.CodeOf(err)
	}
	other := strings.Repeat("a", 64)
	// Nothing confirmed yet.
	for _, tc := range []struct {
		opts     enterpriseSecretOptions
		stored   string
		storedOK bool
		want     enterprisebundle.Code
	}{
		{enterpriseSecretOptions{}, "key-2", true, ""},
		{enterpriseSecretOptions{bundle: "b", ifConfirmed: "none"}, "key-1", true, ""},
		{enterpriseSecretOptions{bundle: "b", ifConfirmed: other}, "key-1", true, codeConfirmedBundleChanged},
		{enterpriseSecretOptions{undoRotation: "none"}, "key-2", true, ""},
		{enterpriseSecretOptions{undoRotation: "none"}, "", false, "credential_changed"},
		{enterpriseSecretOptions{undoRotation: other}, "key-2", true, codeRotationConfirmed},
	} {
		if got := check(tc.opts, tc.stored, tc.storedOK); got != tc.want {
			t.Fatalf("nothing confirmed, %+v stored %q: got %q, want %q", tc.opts, tc.stored, got, tc.want)
		}
	}
	rotated := sha256.Sum256([]byte("key-2"))
	if got := check(enterpriseSecretOptions{undoRotation: "none", ifStored: hex.EncodeToString(rotated[:])}, "admin-key", true); got != "credential_changed" {
		t.Fatalf("a later administrator value: got %q, want credential_changed", got)
	}
	v5 := e.signCredentialBundle(t, "5", "key-1", key)
	confirmSignedBundle(t, store, v5)
	p5 := manifestSHA(v5)
	for _, tc := range []struct {
		name     string
		opts     enterpriseSecretOptions
		stored   string
		storedOK bool
		want     enterprisebundle.Code
	}{
		{"rotation while the journaled bundle is confirmed", enterpriseSecretOptions{bundle: "b", ifConfirmed: p5}, "key-1", true, ""},
		{"rotation after another bundle was confirmed", enterpriseSecretOptions{bundle: "b", ifConfirmed: "none"}, "key-1", true, codeConfirmedBundleChanged},
		// The failed apply left v5 confirmed with the new value (the
		// finding: v5 references the credential and none was stored, so
		// the rotation added it): put back, whatever v5 references.
		{"put-back of a value v5 does not sign", enterpriseSecretOptions{undoRotation: p5}, "key-2", true, ""},
		{"put-back with nothing stored", enterpriseSecretOptions{undoRotation: p5}, "", false, "credential_changed"},
		// v5 itself signs what is stored now (a redelivery of v5, or a run
		// stopped before its rotation): kept.
		{"put-back of the value v5 signs", enterpriseSecretOptions{undoRotation: p5}, "key-1", true, codeRotationConfirmed},
		{"put-back of the value v5 signs, with a line ending", enterpriseSecretOptions{undoRotation: p5}, "key-1\n", true, codeRotationConfirmed},
		// A bundle was confirmed since the rotation: kept.
		{"put-back journaled before any bundle", enterpriseSecretOptions{undoRotation: "none"}, "key-2", true, codeRotationConfirmed},
		{"put-back journaled under another bundle", enterpriseSecretOptions{undoRotation: other}, "", false, "credential_changed"},
	} {
		if got := check(tc.opts, tc.stored, tc.storedOK); got != tc.want {
			t.Fatalf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
	// The rotation's bundle confirmed: every put-back journaled under v5 is
	// refused rotation_confirmed, whatever is stored.
	v6 := e.signCredentialBundle(t, "6", "key-2", key)
	confirmSignedBundle(t, store, v6)
	for _, stored := range []string{"key-1", "key-2", ""} {
		want := codeRotationConfirmed
		if stored == "" {
			want = "credential_changed"
		}
		if got := check(enterpriseSecretOptions{undoRotation: p5}, stored, stored != ""); got != want {
			t.Fatalf("v6 confirmed, stored %q: got %q, want %q", stored, got, want)
		}
	}
	if got := check(enterpriseSecretOptions{undoRotation: manifestSHA(v6)}, "key-2", true); got != codeRotationConfirmed {
		t.Fatalf("v6 confirmed and signs the stored value: got %q", got)
	}
	if got := check(enterpriseSecretOptions{undoRotation: manifestSHA(v6)}, "key-3", true); got != "" {
		t.Fatalf("v6 confirmed and does not sign the stored value: got %q", got)
	}
	if code := secretBindingCode(checkSecretTransaction(name, &enterpriseSecretOptions{undoRotation: p5, ifStored: strings.Repeat("0", 64)}, nil, false)); code != "credential_changed" {
		t.Fatalf("errors[].code %q", code)
	}
}

func TestSecretTransactionArgumentsRefuseAMeaninglessCombination(t *testing.T) {
	digest := strings.Repeat("0", 64)
	for _, tc := range []struct {
		opts enterpriseSecretOptions
		ok   bool
	}{
		{enterpriseSecretOptions{}, true},
		{enterpriseSecretOptions{bundle: "b", ifConfirmed: digest}, true},
		{enterpriseSecretOptions{bundle: "b", ifConfirmed: "none"}, true},
		{enterpriseSecretOptions{undoRotation: digest, ifStored: digest}, true},
		{enterpriseSecretOptions{undoRotation: "none", ifStored: digest}, true},
		{enterpriseSecretOptions{bundle: "b", ifConfirmed: "none", ifStored: "none"}, runtime.GOOS == "windows"},
		{enterpriseSecretOptions{undoRotation: "none", ifStored: "none"}, runtime.GOOS == "windows"},
		{enterpriseSecretOptions{undoRotation: digest}, false},
		{enterpriseSecretOptions{ifStored: "bad"}, false},
		{enterpriseSecretOptions{ifStored: "None"}, false},
		{enterpriseSecretOptions{ifConfirmed: digest}, false},
		{enterpriseSecretOptions{bundle: "b", undoRotation: digest}, false},
		{enterpriseSecretOptions{bundle: "b", ifConfirmed: digest, undoRotation: digest}, false},
		{enterpriseSecretOptions{undoRotation: strings.ToUpper(strings.Repeat("a", 64))}, false},
		{enterpriseSecretOptions{undoRotation: "sha256:" + digest}, false},
		{enterpriseSecretOptions{bundle: "b", ifConfirmed: "None"}, false},
		// Loop round 1 (review at b97e9ab4): --undo-config names the config
		// installed before the rotation, for a put-back only.
		{enterpriseSecretOptions{undoRotation: digest, undoConfig: digest, ifStored: digest}, true},
		{enterpriseSecretOptions{undoRotation: "none", undoConfig: "none", ifStored: digest}, true},
		{enterpriseSecretOptions{undoConfig: digest}, false},
		{enterpriseSecretOptions{bundle: "b", ifConfirmed: digest, undoConfig: digest}, false},
		{enterpriseSecretOptions{undoRotation: digest, undoConfig: "sha256:" + digest}, false},
		{enterpriseSecretOptions{undoRotation: digest, undoConfig: strings.ToUpper(strings.Repeat("a", 64))}, false},
	} {
		if err := secretTransactionArguments(&tc.opts); (err == nil) != tc.ok {
			t.Fatalf("%+v: %v, want ok=%v", tc.opts, err, tc.ok)
		}
	}
}

// Loop round 1 (review at b97e9ab4): a put-back took a credential the
// installed config references whatever that config was, so it removed a
// credential a config installed after the rotation uses. It takes one only
// while the config the wrapper journaled before the rotation (--undo-config)
// is the one installed: the exact bytes, never "none", never without
// --undo-rotation.
func TestUndoRotationOnConfigTakesOnlyTheConfigFromBeforeTheRotation(t *testing.T) {
	before := []byte("config_version: 8\n# installed before the rotation\n")
	sum := sha256.Sum256(before)
	journaled := hex.EncodeToString(sum[:])
	for _, tc := range []struct {
		name      string
		opts      enterpriseSecretOptions
		installed []byte
		want      bool
	}{
		{"the config from before, nothing confirmed", enterpriseSecretOptions{undoRotation: "none", undoConfig: journaled}, before, true},
		{"the config from before, a bundle confirmed", enterpriseSecretOptions{undoRotation: strings.Repeat("b", 64), undoConfig: journaled}, before, true},
		{"a config installed since", enterpriseSecretOptions{undoRotation: "none", undoConfig: journaled}, []byte("config_version: 8\n# installed since\n"), false},
		{"the config from before, rewritten with one more byte", enterpriseSecretOptions{undoRotation: "none", undoConfig: journaled}, append(append([]byte{}, before...), '\n'), false},
		{"no config journaled", enterpriseSecretOptions{undoRotation: "none"}, before, false},
		{"no config installed before the rotation", enterpriseSecretOptions{undoRotation: "none", undoConfig: "none"}, before, false},
		{"no config either time", enterpriseSecretOptions{undoRotation: "none", undoConfig: "none"}, nil, false},
		{"not a put-back", enterpriseSecretOptions{undoConfig: journaled}, before, false},
		{"upper-case digest", enterpriseSecretOptions{undoRotation: "none", undoConfig: strings.ToUpper(journaled)}, before, false},
	} {
		if got := undoRotationOnConfig(&tc.opts, tc.installed); got != tc.want {
			t.Fatalf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}
