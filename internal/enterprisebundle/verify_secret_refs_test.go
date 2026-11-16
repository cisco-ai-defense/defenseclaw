// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// testSecretValue is the value a test bundle binds for credential name.
func testSecretValue(name string) []byte { return []byte("value-of-" + name) }

// bindValues gives Compose the test value of every named credential.
func bindValues(names ...string) func(*enterprisebundle.ComposeInput) {
	return func(in *enterprisebundle.ComposeInput) {
		in.SecretValues = map[string][]byte{}
		for _, name := range names {
			in.SecretValues[name] = testSecretValue(name)
		}
	}
}

// boundRef is a secret_refs entry that binds the test value of name.
func boundRef(name string, required bool) enterprisebundle.SecretRef {
	return enterprisebundle.SecretRef{Ref: enterprisebundle.SecretRefScheme + name, Required: required,
		ValueSHA256: enterprisebundle.CredentialValueSHA256("acme", name, testSecretValue(name))}
}

// secretRefsFixture signs a bundle whose manifest lists a required
// credential config.yaml names, an optional one and a second required one,
// in that order, each bound to its test value.
func secretRefsFixture(t *testing.T) (*fixture, *enterprisebundle.Bundle, *enterprisebundle.Anchors) {
	t.Helper()
	return signedSecretRefs(t, boundRef("ai-defense-api-key", true), boundRef("zz-optional", false), boundRef("splunk-token", true))
}

// signedSecretRefs signs a bundle of the credential test config whose
// manifest lists refs.
func signedSecretRefs(t *testing.T, refs ...enterprisebundle.SecretRef) (*fixture, *enterprisebundle.Bundle, *enterprisebundle.Anchors) {
	t.Helper()
	cfg := strings.Replace(bundleConfig(t), "  profile: standalone\n", "  profile: standalone\n  inspection:\n    ai_defense:\n      credential: ai-defense-api-key\n", 1)
	f := newFixture(t, cfg, bindValues("ai-defense-api-key"))
	m, err := enterprisebundle.DecodeManifest(f.raw)
	if err != nil {
		t.Fatal(err)
	}
	m.SecretRefs = refs
	raw, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return f, f.signed(t, raw), anchors(t, "acme", nil, 0, activeKey("k1", f.key.Public()))
}

// presentOnly is a credential store that holds the test value of names and
// counts lookups.
func presentOnly(lookups map[string]int, names ...string) func(string) ([]byte, error) {
	return func(name string) ([]byte, error) {
		lookups[name]++
		if !slices.Contains(names, name) {
			return nil, nil
		}
		return testSecretValue(name), nil
	}
}

// storeOf is a credential store that holds values.
func storeOf(values map[string]string) func(string) ([]byte, error) {
	return func(name string) ([]byte, error) {
		value, ok := values[name]
		if !ok {
			return nil, nil
		}
		return []byte(value), nil
	}
}

// A secret_refs entry that signs only the credential name (every bundle
// signed before 1.0.4) leaves the value the gateway uses unauthenticated:
// verify refuses it secret_ref_unbound, also off a device, before any store
// lookup.
func TestVerifyRefusesASecretRefThatBindsNoValue(t *testing.T) {
	f := newFixture(t, bundleConfig(t), nil)
	m, err := enterprisebundle.DecodeManifest(f.raw)
	if err != nil {
		t.Fatal(err)
	}
	m.SecretRefs = []enterprisebundle.SecretRef{{Ref: "secret://splunk-token", Required: true}}
	raw, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	a := anchors(t, "acme", nil, 0, activeKey("k1", f.key.Public()))
	if _, err := enterprisebundle.Verify(context.Background(), f.input(t, f.signed(t, raw), a)); enterprisebundle.CodeOf(err) != "secret_ref_unbound" ||
		!strings.Contains(err.Error(), "splunk-token") {
		t.Fatalf("name-only reference off a device: got %v, want secret_ref_unbound", err)
	}
}

// On a device the name-only reference refuses before any credential is
// read.
func TestVerifyRefusesANameOnlySecretRefBeforeTheStoreLookup(t *testing.T) {
	f, b, a := signedSecretRefs(t, enterprisebundle.SecretRef{Ref: "secret://ai-defense-api-key", Required: true})
	in := f.input(t, b, a)
	lookups := map[string]int{}
	in.SecretValue, in.RequireSecretPresence = presentOnly(lookups, "ai-defense-api-key"), true
	if _, err := enterprisebundle.Verify(context.Background(), in); enterprisebundle.CodeOf(err) != enterprisebundle.CodeSecretRefUnbound || len(lookups) != 0 {
		t.Fatalf("name-only reference on a device: got %v after lookups %v, want secret_ref_unbound before any lookup", err, lookups)
	}
}

// A device that stores another value than the one the bundle signs refuses
// it secret_ref_mismatch, required and optional references alike, and lists
// every such credential (never a value). The value is compared as the
// gateway reads it (surrounding whitespace trimmed), and a digest is only
// valid for the tenant and the name it was signed for.
func TestVerifyRefusesAStoredCredentialTheBundleDoesNotSign(t *testing.T) {
	f, b, a := secretRefsFixture(t)
	signed := map[string]string{
		"ai-defense-api-key": string(testSecretValue("ai-defense-api-key")),
		"zz-optional":        string(testSecretValue("zz-optional")),
		"splunk-token":       string(testSecretValue("splunk-token")),
	}
	with := func(name, value string) map[string]string {
		out := map[string]string{}
		for k, v := range signed {
			out[k] = v
		}
		out[name] = value
		return out
	}
	for _, tc := range []struct {
		name     string
		store    map[string]string
		refusal  string
		mismatch []string
	}{
		{"required rotated outside the bundle", with("splunk-token", "attacker-token"), "splunk-token", []string{"splunk-token"}},
		{"optional rotated outside the bundle", with("zz-optional", "other"), "zz-optional", []string{"zz-optional"}},
		{"the value of another credential", with("ai-defense-api-key", signed["splunk-token"]), "ai-defense-api-key", []string{"ai-defense-api-key"}},
		{"surrounding whitespace", with("splunk-token", " "+signed["splunk-token"]+"\n"), "", []string{}},
		{"all signed", signed, "", []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := f.input(t, b, a)
			in.SecretValue, in.RequireSecretPresence = storeOf(tc.store), true
			res, err := enterprisebundle.Verify(context.Background(), in)
			if tc.refusal == "" {
				if err != nil {
					t.Fatalf("verify: %v", err)
				}
			} else if enterprisebundle.CodeOf(err) != enterprisebundle.CodeSecretRefMismatch || !strings.Contains(err.Error(), "credential "+tc.refusal) {
				t.Fatalf("verify: got %v, want secret_ref_mismatch naming %s", err, tc.refusal)
			}
			if !slices.Equal(res.SecretRefsMismatch, tc.mismatch) || !slices.Equal(res.SecretRefsMissing, []string{}) {
				t.Fatalf("mismatch %#v missing %#v, want mismatch %#v", res.SecretRefsMismatch, res.SecretRefsMissing, tc.mismatch)
			}
			if err != nil && strings.Contains(err.Error(), "attacker-token") {
				t.Fatalf("the refusal prints the stored value: %v", err)
			}
		})
	}

	// The digest binds the tenant: the same value signed for another tenant
	// is not this bundle's.
	other := boundRef("ai-defense-api-key", true)
	other.ValueSHA256 = enterprisebundle.CredentialValueSHA256("other-tenant", "ai-defense-api-key", testSecretValue("ai-defense-api-key"))
	f, b, a = signedSecretRefs(t, other)
	in := f.input(t, b, a)
	in.SecretValue = storeOf(signed)
	if _, err := enterprisebundle.Verify(context.Background(), in); enterprisebundle.CodeOf(err) != enterprisebundle.CodeSecretRefMismatch {
		t.Fatalf("digest of another tenant: got %v, want secret_ref_mismatch", err)
	}
}

// Compose binds every credential config.yaml references to the value the
// signer gave and refuses a credential without one (secret_ref_unbound) and
// a value for a credential config.yaml does not reference.
func TestComposeBindsEveryCredentialValue(t *testing.T) {
	cfg := strings.Replace(bundleConfig(t), "  profile: standalone\n", "  profile: standalone\n  inspection:\n    ai_defense:\n      credential: ai-defense-api-key\n", 1)
	root, files := writeBundle(t, cfg)
	in := enterprisebundle.ComposeInput{
		Bundle: files, Root: root, BundleID: tamperBundleID, TenantID: "acme", DeviceGroup: "eng", Version: 5,
		CreatedAt: signedAt, CreatedBy: "operator:alice", ProductVersion: "1.0.2", HostPlatform: runtime.GOOS, Digester: digester,
	}
	if _, _, err := enterprisebundle.Compose(context.Background(), in); enterprisebundle.CodeOf(err) != enterprisebundle.CodeSecretRefUnbound ||
		!strings.Contains(err.Error(), "--secret-file ai-defense-api-key=") {
		t.Fatalf("no value: got %v, want secret_ref_unbound naming --secret-file", err)
	}
	in.SecretValues = map[string][]byte{"ai-defense-api-key": []byte("key-1"), "splunk-token": []byte("t")}
	if _, _, err := enterprisebundle.Compose(context.Background(), in); enterprisebundle.CodeOf(err) != enterprisebundle.CodeManifestInvalid || !strings.Contains(err.Error(), "splunk-token") {
		t.Fatalf("value for an unreferenced credential: got %v, want manifest_invalid", err)
	}
	delete(in.SecretValues, "splunk-token")
	m, raw, err := enterprisebundle.Compose(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	want := enterprisebundle.CredentialValueSHA256("acme", "ai-defense-api-key", []byte("key-1"))
	if len(m.SecretRefs) != 1 || m.SecretRefs[0].ValueSHA256 != want || strings.Contains(string(raw), "key-1") {
		t.Fatalf("secret_refs %+v; want value_sha256 %s and no value in the manifest", m.SecretRefs, want)
	}
}

// secret set stores a credential the confirmed bundle references only with
// the value it signs; a new value needs a newer verified bundle (--bundle)
// that signs it. A credential no bundle references is not checked.
func TestCheckCredentialChange(t *testing.T) {
	manifest := func(refs ...enterprisebundle.SecretRef) *enterprisebundle.Manifest {
		return &enterprisebundle.Manifest{TenantID: "acme", SecretRefs: refs}
	}
	signedFor := func(name, value string) enterprisebundle.SecretRef {
		return enterprisebundle.SecretRef{Ref: enterprisebundle.SecretRefScheme + name, Required: true,
			ValueSHA256: enterprisebundle.CredentialValueSHA256("acme", name, []byte(value))}
	}
	confirmed := manifest(signedFor("splunk-token", "v1"), enterprisebundle.SecretRef{Ref: "secret://legacy-key", Required: true})
	rotation := manifest(signedFor("splunk-token", "v2"))
	for _, tc := range []struct {
		name                string
		confirmed, rotation *enterprisebundle.Manifest
		credential, value   string
		want                enterprisebundle.Code
	}{
		{"no bundle confirmed", nil, nil, "splunk-token", "anything", ""},
		{"the signed value", confirmed, nil, "splunk-token", "v1", ""},
		{"the signed value with a line ending", confirmed, nil, "splunk-token", "v1\n", ""},
		{"another value", confirmed, nil, "splunk-token", "v2", enterprisebundle.CodeSecretRefMismatch},
		{"a name-only reference", confirmed, nil, "legacy-key", "v1", enterprisebundle.CodeSecretRefUnbound},
		{"a credential no bundle references", confirmed, nil, "other-key", "v9", ""},
		{"rotation to the value the new bundle signs", confirmed, rotation, "splunk-token", "v2", ""},
		{"rotation to another value", confirmed, rotation, "splunk-token", "v3", enterprisebundle.CodeSecretRefMismatch},
		{"rotation keeps the old value", confirmed, rotation, "splunk-token", "v1", enterprisebundle.CodeSecretRefMismatch},
		{"rotation bundle without the credential", confirmed, rotation, "other-key", "v9", enterprisebundle.CodeSecretRefMismatch},
		{"rotation with no bundle confirmed", nil, rotation, "splunk-token", "v2", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := enterprisebundle.CheckCredentialChange(tc.confirmed, tc.rotation, tc.credential, []byte(tc.value))
			if enterprisebundle.CodeOf(err) != tc.want || (tc.want == "") != (err == nil) {
				t.Fatalf("got %v, want code %q", err, tc.want)
			}
		})
	}
}

// Verify looks every reference up and lists every missing one, required
// and optional, in manifest order; a refusal still names the first
// required credential missing (secret_ref_missing), as before.
func TestVerifyListsEveryMissingSecretRef(t *testing.T) {
	f, b, a := secretRefsFixture(t)
	for _, tc := range []struct {
		name     string
		present  []string
		refusal  string
		missing  []string
		verified bool
	}{
		{"none stored", nil, "ai-defense-api-key", []string{"ai-defense-api-key", "zz-optional", "splunk-token"}, false},
		{"first stored", []string{"ai-defense-api-key"}, "splunk-token", []string{"zz-optional", "splunk-token"}, false},
		{"only the optional missing", []string{"ai-defense-api-key", "splunk-token"}, "", []string{"zz-optional"}, true},
		{"all stored", []string{"ai-defense-api-key", "splunk-token", "zz-optional"}, "", []string{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lookups := map[string]int{}
			in := f.input(t, b, a)
			in.SecretValue = presentOnly(lookups, tc.present...)
			res, err := enterprisebundle.Verify(context.Background(), in)
			if tc.verified {
				if err != nil {
					t.Fatalf("verify: %v", err)
				}
			} else if enterprisebundle.CodeOf(err) != enterprisebundle.CodeSecretRefMissing || !strings.Contains(err.Error(), "credential "+tc.refusal) {
				t.Fatalf("verify: got %v, want secret_ref_missing naming %s", err, tc.refusal)
			}
			if res.SecretRefsMissing == nil || !slices.Equal(res.SecretRefsMissing, tc.missing) {
				t.Fatalf("secret refs missing = %#v, want %#v", res.SecretRefsMissing, tc.missing)
			}
			for _, name := range []string{"ai-defense-api-key", "zz-optional", "splunk-token"} {
				if lookups[name] != 1 {
					t.Fatalf("credential %s looked up %d times, want once: %v", name, lookups[name], lookups)
				}
			}
		})
	}
}

// A stored credential the gateway's read refuses (managed
// ErrUnusableServiceCredential: an extra reader ACE, empty, too large) is
// missing, not unchecked: a required one refuses, an optional one is listed,
// and it never hides the state of another reference (review of GAP-0009).
func TestVerifyCountsUnusableCredentialAsMissing(t *testing.T) {
	f, b, a := secretRefsFixture(t)
	unusable := fmt.Errorf("principal S-1-5-32-545 may read the protected credential: %w", managed.ErrUnusableServiceCredential)
	store := func(errs map[string]error) func(string) ([]byte, error) {
		return func(name string) ([]byte, error) {
			err, ok := errs[name]
			if !ok {
				err = managed.ErrNoServiceCredential
			}
			return managed.ServiceCredentialValue(testSecretValue(name), err)
		}
	}
	in := f.input(t, b, a)
	in.SecretValue = store(map[string]error{"ai-defense-api-key": unusable, "zz-optional": nil, "splunk-token": nil})
	res, err := enterprisebundle.Verify(context.Background(), in)
	if enterprisebundle.CodeOf(err) != enterprisebundle.CodeSecretRefMissing || !strings.Contains(err.Error(), "credential ai-defense-api-key") {
		t.Fatalf("unusable required credential: got %v, want secret_ref_missing", err)
	}
	if !slices.Equal(res.SecretRefsMissing, []string{"ai-defense-api-key"}) || hasWarning(res.Warnings, enterprisebundle.WarnSecretPresenceUnchecked) {
		t.Fatalf("unusable required credential: missing %#v, warnings %+v", res.SecretRefsMissing, res.Warnings)
	}

	in.SecretValue = store(map[string]error{"ai-defense-api-key": nil, "zz-optional": unusable, "splunk-token": nil})
	res, err = enterprisebundle.Verify(context.Background(), in)
	if err != nil || !slices.Equal(res.SecretRefsMissing, []string{"zz-optional"}) || hasWarning(res.Warnings, enterprisebundle.WarnSecretPresenceUnchecked) {
		t.Fatalf("unusable optional credential: missing %#v, warnings %+v, err %v", res.SecretRefsMissing, res.Warnings, err)
	}
}

// The list is absent unless every reference was checked: off a device (no
// presence reader) and with a store that cannot be read for one name, which
// warns secret_presence_unchecked, also on the refusal for another required
// credential that is missing.
func TestVerifyOmitsSecretRefsMissingWhenPresenceWasNotChecked(t *testing.T) {
	f, b, a := secretRefsFixture(t)
	res, err := enterprisebundle.Verify(context.Background(), f.input(t, b, a))
	if err != nil || res.SecretRefsMissing != nil {
		t.Fatalf("off a device: missing %#v, err %v", res.SecretRefsMissing, err)
	}

	unreadable := func(fail string, present ...string) func(string) ([]byte, error) {
		return func(name string) ([]byte, error) {
			if name == fail {
				return nil, os.ErrPermission
			}
			return presentOnly(map[string]int{}, present...)(name)
		}
	}
	in := f.input(t, b, a)
	in.SecretValue = unreadable("zz-optional", "ai-defense-api-key", "splunk-token")
	res, err = enterprisebundle.Verify(context.Background(), in)
	if err != nil || res.SecretRefsMissing != nil || !hasWarning(res.Warnings, enterprisebundle.WarnSecretPresenceUnchecked) {
		t.Fatalf("one unreadable credential: missing %#v, warnings %+v, err %v", res.SecretRefsMissing, res.Warnings, err)
	}

	in.SecretValue = unreadable("zz-optional", "ai-defense-api-key")
	res, err = enterprisebundle.Verify(context.Background(), in)
	if enterprisebundle.CodeOf(err) != enterprisebundle.CodeSecretRefMissing || !strings.Contains(err.Error(), "splunk-token") || res.SecretRefsMissing != nil {
		t.Fatalf("unreadable credential and a missing required one: missing %#v, err %v", res.SecretRefsMissing, err)
	}
	if !hasWarning(res.Warnings, enterprisebundle.WarnSecretPresenceUnchecked) {
		t.Fatalf("unreadable credential and a missing required one: the refusal dropped the unchecked warning: %+v", res.Warnings)
	}
	var be *enterprisebundle.Error
	if !errors.As(err, &be) || be.Path != "secret_refs" {
		t.Fatalf("refusal path: %+v", err)
	}
}

// Rendered is the config Verify validated. The apply installs the same file
// rendered against its version directory: the two renderings differ only in
// values that need no restart, so a restart prediction from Rendered equals
// the classification of the bytes the apply installs (hot and restart-
// required bundles alike).
func TestVerifyRenderedPredictsTheApplyClassification(t *testing.T) {
	base := bundleConfig(t)
	installedFixture := newFixture(t, base, nil)
	installed, err := enterprisebundle.RenderConfig(installedFixture.bundle, "/etc/defenseclaw/bundles/v4-b-old-r-old")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, config string
		restart      bool
	}{
		{"same settings", base, false},
		{"hot mode change", strings.Replace(base, guardrailMode, "guardrail:\n  enabled: true\n  mode: action\n", 1), false},
		{"restart-required key", strings.Replace(base, guardrailMode, guardrailMode+"  hook_self_heal: false\n", 1), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.config == base && tc.name != "same settings" {
				t.Fatal("test config has no guardrail mode to change")
			}
			f := newFixture(t, tc.config, nil)
			a := anchors(t, "acme", nil, 0, activeKey("k1", f.key.Public()))
			res, err := enterprisebundle.Verify(context.Background(), f.input(t, f.bundle, a))
			if err != nil || len(res.Rendered) == 0 {
				t.Fatalf("verify: rendered %d bytes, err %v", len(res.Rendered), err)
			}
			applied, err := enterprisebundle.RenderConfig(f.bundle, "/etc/defenseclaw/bundles/v5-b-new-r-new")
			if err != nil {
				t.Fatal(err)
			}
			between, err := configwrite.ChangedPaths(res.Rendered, applied)
			if err != nil {
				t.Fatal(err)
			}
			if restart := configwrite.ManagedRestartRequired(between); len(restart) != 0 {
				t.Fatalf("the verify and apply renderings differ in restart-required keys %v", restart)
			}
			predicted, err := configwrite.ManagedConfigRestartRequired(installed, res.Rendered, configwrite.ManagedDefaults{})
			if err != nil {
				t.Fatal(err)
			}
			actual, err := configwrite.ManagedConfigRestartRequired(installed, applied, configwrite.ManagedDefaults{})
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(predicted, actual) || (len(actual) > 0) != tc.restart {
				t.Fatalf("predicted %v, the applied config classifies %v (restart %v)", predicted, actual, tc.restart)
			}
		})
	}
}

// guardrailMode is the guardrail block of the test bundle config.
const guardrailMode = "guardrail:\n  enabled: true\n  mode: observe\n"

func hasWarning(warnings []enterprisebundle.Warning, code string) bool {
	for _, w := range warnings {
		if w.Code == code {
			return true
		}
	}
	return false
}

// The apply sets RequireSecretPresence: a required credential whose lookup
// failed refuses secret_ref_missing (with the secret_presence_unchecked
// warning) instead of letting the apply pass the credential gate. An
// optional one only warns; read-only verify keeps the warning alone.
func TestVerifyRequireSecretPresenceRefusesARequiredCredentialItCannotCheck(t *testing.T) {
	f, b, a := secretRefsFixture(t)
	unreadable := func(fail string) func(string) ([]byte, error) {
		return func(name string) ([]byte, error) {
			if name == fail {
				return nil, os.ErrPermission
			}
			return testSecretValue(name), nil
		}
	}
	in := f.input(t, b, a)
	in.SecretValue = unreadable("splunk-token")
	if _, err := enterprisebundle.Verify(context.Background(), in); err != nil {
		t.Fatalf("read-only verify with an unchecked required credential: %v, want the warning only", err)
	}
	in.RequireSecretPresence = true
	res, err := enterprisebundle.Verify(context.Background(), in)
	if enterprisebundle.CodeOf(err) != enterprisebundle.CodeSecretRefMissing || !strings.Contains(err.Error(), "splunk-token could not be checked") {
		t.Fatalf("apply with an unchecked required credential: got %v, want secret_ref_missing", err)
	}
	if res.SecretRefsMissing != nil || !hasWarning(res.Warnings, enterprisebundle.WarnSecretPresenceUnchecked) {
		t.Fatalf("apply refusal: missing %#v, warnings %+v", res.SecretRefsMissing, res.Warnings)
	}
	in.SecretValue = unreadable("zz-optional")
	res, err = enterprisebundle.Verify(context.Background(), in)
	if err != nil || !hasWarning(res.Warnings, enterprisebundle.WarnSecretPresenceUnchecked) {
		t.Fatalf("apply with an unchecked optional credential: warnings %+v, err %v; want the warning only", res.Warnings, err)
	}
}

// Verify lists every secret_refs entry with its state in manifest order,
// exactly when it lists the missing and mismatched names, and the list holds
// names and booleans only (private #16).
func TestVerifyListsTheStateOfEverySecretRef(t *testing.T) {
	f, b, a := secretRefsFixture(t)
	res, err := enterprisebundle.Verify(context.Background(), f.input(t, b, a))
	if err != nil || res.SecretRefs != nil {
		t.Fatalf("off a device: secret refs %#v, err %v", res.SecretRefs, err)
	}

	in := f.input(t, b, a)
	in.SecretValue = storeOf(map[string]string{
		"ai-defense-api-key": string(testSecretValue("ai-defense-api-key")),
		"zz-optional":        "another-value",
	})
	res, err = enterprisebundle.Verify(context.Background(), in)
	if enterprisebundle.CodeOf(err) != enterprisebundle.CodeSecretRefMismatch {
		t.Fatalf("verify: got %v, want secret_ref_mismatch (the optional credential comes first)", err)
	}
	want := []enterprisebundle.SecretRefState{
		{Name: "ai-defense-api-key", Required: true, Present: true, ValueMatch: true},
		{Name: "zz-optional", Required: false, Present: true, ValueMatch: false},
		{Name: "splunk-token", Required: true, Present: false, ValueMatch: false},
	}
	if !slices.Equal(res.SecretRefs, want) {
		t.Fatalf("secret refs = %#v, want %#v", res.SecretRefs, want)
	}
	if res.SecretRefsMissing == nil {
		t.Fatal("secret_refs set without secret_refs_missing")
	}
	raw, err := json.Marshal(res.SecretRefs)
	if err != nil {
		t.Fatal(err)
	}
	var entries []map[string]any
	if err := json.Unmarshal(raw, &entries); err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		keys := make([]string, 0, len(entry))
		for key := range entry {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		if !slices.Equal(keys, []string{"name", "present", "required", "value_match"}) {
			t.Fatalf("secret_refs entry members %v, want name, present, required, value_match only", keys)
		}
	}
	if strings.Contains(string(raw), "another-value") || strings.Contains(string(raw), "sha256") {
		t.Fatalf("secret_refs carries a value or digest: %s", raw)
	}
}
