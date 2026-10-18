// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// secretRefsFixture signs a bundle whose manifest lists a required
// credential config.yaml names, an optional one and a second required one,
// in that order.
func secretRefsFixture(t *testing.T) (*fixture, *enterprisebundle.Bundle, *enterprisebundle.Anchors) {
	t.Helper()
	cfg := strings.Replace(bundleConfig(t), "  profile: standalone\n", "  profile: standalone\n  inspection:\n    ai_defense:\n      credential: ai-defense-api-key\n", 1)
	f := newFixture(t, cfg, nil)
	m, err := enterprisebundle.DecodeManifest(f.raw)
	if err != nil {
		t.Fatal(err)
	}
	m.SecretRefs = []enterprisebundle.SecretRef{
		{Ref: "secret://ai-defense-api-key", Required: true},
		{Ref: "secret://zz-optional", Required: false},
		{Ref: "secret://splunk-token", Required: true},
	}
	raw, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return f, f.signed(t, raw), anchors(t, "acme", nil, 0, activeKey("k1", f.key.Public()))
}

// presentOnly is a credential store that holds names and counts lookups.
func presentOnly(lookups map[string]int, names ...string) func(string) (bool, error) {
	return func(name string) (bool, error) {
		lookups[name]++
		return slices.Contains(names, name), nil
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
			in.SecretPresent = presentOnly(lookups, tc.present...)
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
	store := func(errs map[string]error) func(string) (bool, error) {
		return func(name string) (bool, error) {
			err, ok := errs[name]
			if !ok {
				err = managed.ErrNoServiceCredential
			}
			return managed.ServiceCredentialPresence(err)
		}
	}
	in := f.input(t, b, a)
	in.SecretPresent = store(map[string]error{"ai-defense-api-key": unusable, "zz-optional": nil, "splunk-token": nil})
	res, err := enterprisebundle.Verify(context.Background(), in)
	if enterprisebundle.CodeOf(err) != enterprisebundle.CodeSecretRefMissing || !strings.Contains(err.Error(), "credential ai-defense-api-key") {
		t.Fatalf("unusable required credential: got %v, want secret_ref_missing", err)
	}
	if !slices.Equal(res.SecretRefsMissing, []string{"ai-defense-api-key"}) || hasWarning(res.Warnings, enterprisebundle.WarnSecretPresenceUnchecked) {
		t.Fatalf("unusable required credential: missing %#v, warnings %+v", res.SecretRefsMissing, res.Warnings)
	}

	in.SecretPresent = store(map[string]error{"ai-defense-api-key": nil, "zz-optional": unusable, "splunk-token": nil})
	res, err = enterprisebundle.Verify(context.Background(), in)
	if err != nil || !slices.Equal(res.SecretRefsMissing, []string{"zz-optional"}) || hasWarning(res.Warnings, enterprisebundle.WarnSecretPresenceUnchecked) {
		t.Fatalf("unusable optional credential: missing %#v, warnings %+v, err %v", res.SecretRefsMissing, res.Warnings, err)
	}
}

// The list is absent unless every reference was checked: off a device (no
// presence reader) and with a store that cannot be read for one name, which
// keeps today's warning, or today's refusal when a required one is missing.
func TestVerifyOmitsSecretRefsMissingWhenPresenceWasNotChecked(t *testing.T) {
	f, b, a := secretRefsFixture(t)
	res, err := enterprisebundle.Verify(context.Background(), f.input(t, b, a))
	if err != nil || res.SecretRefsMissing != nil {
		t.Fatalf("off a device: missing %#v, err %v", res.SecretRefsMissing, err)
	}

	unreadable := func(fail string, present ...string) func(string) (bool, error) {
		return func(name string) (bool, error) {
			if name == fail {
				return false, os.ErrPermission
			}
			return slices.Contains(present, name), nil
		}
	}
	in := f.input(t, b, a)
	in.SecretPresent = unreadable("zz-optional", "ai-defense-api-key", "splunk-token")
	res, err = enterprisebundle.Verify(context.Background(), in)
	if err != nil || res.SecretRefsMissing != nil || !hasWarning(res.Warnings, enterprisebundle.WarnSecretPresenceUnchecked) {
		t.Fatalf("one unreadable credential: missing %#v, warnings %+v, err %v", res.SecretRefsMissing, res.Warnings, err)
	}

	in.SecretPresent = unreadable("zz-optional", "ai-defense-api-key")
	res, err = enterprisebundle.Verify(context.Background(), in)
	if enterprisebundle.CodeOf(err) != enterprisebundle.CodeSecretRefMissing || !strings.Contains(err.Error(), "splunk-token") || res.SecretRefsMissing != nil {
		t.Fatalf("unreadable credential and a missing required one: missing %#v, err %v", res.SecretRefsMissing, err)
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
			predicted, err := configwrite.ManagedConfigRestartRequired(installed, res.Rendered)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := configwrite.ManagedConfigRestartRequired(installed, applied)
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
