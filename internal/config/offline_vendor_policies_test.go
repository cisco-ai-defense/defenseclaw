// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// UseOfflineVendorPolicies redirects only packs under the shipped policy
// folder, keeps the configured paths themselves, and survives DeepCopy (the
// guardrail profiles derive their configs through it) (GAP-0223).
func TestUseOfflineVendorPoliciesRedirectsShippedPacksOnly(t *testing.T) {
	// Each custom pack is a folder (CustomRulePackError); the shipped one
	// exists only in the offline copy.
	vendor := filepath.Join(t.TempDir(), "share", "policies")
	root := t.TempDir()
	own := filepath.Join(t.TempDir(), "policies", "guardrail", "own")
	for _, dir := range []string{filepath.Join(root, "guardrail", "strict"), vendor + "-extra/guardrail/strict", own} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &Config{}
	cfg.Guardrail.CustomPacks = map[string]CustomRulePack{
		"shipped": {Path: vendor + "/guardrail/strict"},
		"sibling": {Path: vendor + "-extra/guardrail/strict"},
		"own":     {Path: own},
	}
	cfg.UseOfflineVendorPolicies(vendor+"/", root)
	copied, err := cfg.DeepCopy()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []*Config{cfg, copied} {
		for _, tc := range []struct {
			ref  RulePackRef
			want string
		}{
			{RulePackRef{Dir: vendor + "/guardrail/default"}, filepath.Join(root, "guardrail", "default")},
			{RulePackRef{Dir: vendor}, root},
			{RulePackRef{Dir: vendor + "/guardrail/../guardrail/default"}, filepath.Join(root, "guardrail", "default")},
			{RulePackRef{Name: "shipped"}, filepath.Join(root, "guardrail", "strict")},
			{RulePackRef{Name: "sibling"}, vendor + "-extra/guardrail/strict"},
			{RulePackRef{Name: "own"}, own},
			{RulePackRef{Dir: "/opt/defenseclaw/share/policy/guardrail/default"}, "/opt/defenseclaw/share/policy/guardrail/default"},
			{RulePackRef{}, ""},
		} {
			if got := c.ResolveRulePackDir(tc.ref); got != tc.want {
				t.Errorf("ResolveRulePackDir(%+v) = %q, want %q", tc.ref, got, tc.want)
			}
		}
	}
	if cfg.Guardrail.CustomPacks["shipped"].Path != vendor+"/guardrail/strict" {
		t.Fatalf("the configured path changed: %q", cfg.Guardrail.CustomPacks["shipped"].Path)
	}
	plain := &Config{}
	if got := plain.ResolveRulePackDir(RulePackRef{Dir: vendor + "/guardrail/default"}); got != vendor+"/guardrail/default" {
		t.Fatalf("a config without the redirect resolved %q", got)
	}
}
