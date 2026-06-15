// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

func TestEvaluateAssetPolicyDisabledAllows(t *testing.T) {
	cfg := &Config{}

	decision := cfg.EvaluateAssetPolicy(AssetPolicyInput{
		TargetType: "mcp",
		Name:       "rogue",
	})

	if decision.Enabled {
		t.Fatal("disabled asset policy should not report enabled")
	}
	if decision.Action != "allow" || decision.RawAction != "allow" {
		t.Fatalf("decision action=%q raw=%q, want allow/allow", decision.Action, decision.RawAction)
	}
}

func TestEvaluateAssetPolicyDeniedBlocksInActionMode(t *testing.T) {
	cfg := &Config{AssetPolicy: DefaultAssetPolicy()}
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = AssetPolicyModeAction
	cfg.AssetPolicy.MCP.Denied = []AssetPolicyRule{{Name: "rogue", Connector: "codex", Reason: "admin deny"}}

	decision := cfg.EvaluateAssetPolicy(AssetPolicyInput{
		TargetType: "mcp",
		Name:       "rogue",
		Connector:  "codex",
	})

	if decision.Action != "block" || decision.RawAction != "block" {
		t.Fatalf("decision action=%q raw=%q, want block/block", decision.Action, decision.RawAction)
	}
	if decision.Source != "admin-deny" {
		t.Fatalf("source=%q, want admin-deny", decision.Source)
	}
	if decision.Reason != "admin deny" {
		t.Fatalf("reason=%q, want admin deny", decision.Reason)
	}
}

func TestEvaluateAssetPolicyDeniedWouldBlockInObserveMode(t *testing.T) {
	cfg := &Config{AssetPolicy: DefaultAssetPolicy()}
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = AssetPolicyModeObserve
	cfg.AssetPolicy.Skill.Denied = []AssetPolicyRule{{Name: "untrusted"}}

	decision := cfg.EvaluateAssetPolicy(AssetPolicyInput{
		TargetType: "skill",
		Name:       "untrusted",
	})

	if decision.Action != "allow" || decision.RawAction != "block" {
		t.Fatalf("decision action=%q raw=%q, want allow/block", decision.Action, decision.RawAction)
	}
	if !decision.WouldBlock {
		t.Fatal("observe-mode denied rule should set WouldBlock")
	}
}

func TestEvaluateAssetPolicyAllowOverridesDefaultDeny(t *testing.T) {
	cfg := &Config{AssetPolicy: DefaultAssetPolicy()}
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = AssetPolicyModeAction
	cfg.AssetPolicy.Plugin.Default = "deny"
	cfg.AssetPolicy.Plugin.Allowed = []AssetPolicyRule{{Name: "trusted-plugin"}}

	decision := cfg.EvaluateAssetPolicy(AssetPolicyInput{
		TargetType: "plugin",
		Name:       "trusted-plugin",
	})

	if decision.Action != "allow" || decision.RawAction != "allow" {
		t.Fatalf("decision action=%q raw=%q, want allow/allow", decision.Action, decision.RawAction)
	}
	if decision.Source != "admin-allow" {
		t.Fatalf("source=%q, want admin-allow", decision.Source)
	}
}

func TestEvaluateAssetPolicyRegistryRequiredBlocksUnknown(t *testing.T) {
	cfg := &Config{AssetPolicy: DefaultAssetPolicy()}
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = AssetPolicyModeAction
	cfg.AssetPolicy.MCP.RegistryRequired = true
	cfg.AssetPolicy.MCP.Registry = []AssetPolicyRule{{Name: "github"}}

	decision := cfg.EvaluateAssetPolicy(AssetPolicyInput{
		TargetType: "mcp",
		Name:       "rogue",
	})

	if decision.Action != "block" || decision.RawAction != "block" {
		t.Fatalf("decision action=%q raw=%q, want block/block", decision.Action, decision.RawAction)
	}
	if decision.Source != "registry-required" {
		t.Fatalf("source=%q, want registry-required", decision.Source)
	}
	if decision.RegistryStatus != "unregistered" {
		t.Fatalf("registry_status=%q, want unregistered", decision.RegistryStatus)
	}
	if !decision.RegistryConfigured {
		t.Fatal("RegistryConfigured = false, want true")
	}
}

// TestEvaluateAssetPolicyRegistryRequiredEmptyDeniesByDefault pins the
// safer fail-closed semantics for registry_required. When an operator
// declares the registry is required but has not (yet) populated it,
// the default behavior is to block all unregistered assets rather
// than silently downgrade to the type policy's Default. Operators must
// explicitly opt into the looser behavior via registry_empty_action.
func TestEvaluateAssetPolicyRegistryRequiredEmptyDeniesByDefault(t *testing.T) {
	cfg := &Config{AssetPolicy: DefaultAssetPolicy()}
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = AssetPolicyModeAction
	cfg.AssetPolicy.MCP.RegistryRequired = true
	// Default is "allow", and yet the empty-registry guard must still
	// block — that is the whole point of the fail-closed default.

	decision := cfg.EvaluateAssetPolicy(AssetPolicyInput{
		TargetType: "mcp",
		Name:       "rogue",
	})

	if decision.Action != "block" || decision.RawAction != "block" {
		t.Fatalf("decision action=%q raw=%q, want block/block", decision.Action, decision.RawAction)
	}
	if decision.Source != "registry-required-empty" {
		t.Fatalf("source=%q, want registry-required-empty", decision.Source)
	}
	if decision.RegistryConfigured {
		t.Fatal("RegistryConfigured = true, want false")
	}
}

func TestEvaluateAssetPolicyRegistryRequiredEmptyAllowOptIn(t *testing.T) {
	cfg := &Config{AssetPolicy: DefaultAssetPolicy()}
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = AssetPolicyModeAction
	cfg.AssetPolicy.MCP.RegistryRequired = true
	cfg.AssetPolicy.MCP.RegistryEmptyAction = "allow"

	decision := cfg.EvaluateAssetPolicy(AssetPolicyInput{
		TargetType: "mcp",
		Name:       "rogue",
	})

	if decision.Action != "allow" || decision.RawAction != "allow" {
		t.Fatalf("decision action=%q raw=%q, want allow/allow", decision.Action, decision.RawAction)
	}
	if decision.Source != "default-allow" {
		t.Fatalf("source=%q, want default-allow", decision.Source)
	}
	if decision.RegistryStatus != "unknown" {
		t.Fatalf("registry_status=%q, want unknown", decision.RegistryStatus)
	}
	if decision.RegistryConfigured {
		t.Fatal("RegistryConfigured = true, want false")
	}
}

// TestEvaluateAssetPolicyRegistryRequiredEmptyAllowOptInRespectsDefaultDeny
// proves the opt-in only relaxes the empty-registry guard — the
// type policy's Default still applies. Without the opt-in this test
// would block at the registry-required-empty step; with it, evaluation
// continues and Default=deny is what produces the block.
func TestEvaluateAssetPolicyRegistryRequiredEmptyAllowOptInRespectsDefaultDeny(t *testing.T) {
	cfg := &Config{AssetPolicy: DefaultAssetPolicy()}
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = AssetPolicyModeAction
	cfg.AssetPolicy.Skill.RegistryRequired = true
	cfg.AssetPolicy.Skill.RegistryEmptyAction = "allow"
	cfg.AssetPolicy.Skill.Default = "deny"

	decision := cfg.EvaluateAssetPolicy(AssetPolicyInput{
		TargetType: "skill",
		Name:       "rogue-skill",
	})

	if decision.Action != "block" || decision.RawAction != "block" {
		t.Fatalf("decision action=%q raw=%q, want block/block", decision.Action, decision.RawAction)
	}
	if decision.Source != "default-deny" {
		t.Fatalf("source=%q, want default-deny", decision.Source)
	}
	if decision.RegistryConfigured {
		t.Fatal("RegistryConfigured = true, want false")
	}
}

// TestEvaluateAssetPolicyRegistryRequiredEmptyMCPDefaultDenyFallsThroughToEmptyGuard
// is the MCP-side companion to the Skill test above for the default
// (no opt-in) case. With registry_required=true + Default=deny + empty
// registry + no opt-in, the empty-registry guard must fire first and
// expose source=registry-required-empty in telemetry — operators
// debugging "why is everything blocked?" need this signal to identify
// that the registry itself is the missing piece.
func TestEvaluateAssetPolicyRegistryRequiredEmptyMCPDefaultDenyFallsThroughToEmptyGuard(t *testing.T) {
	cfg := &Config{AssetPolicy: DefaultAssetPolicy()}
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = AssetPolicyModeAction
	cfg.AssetPolicy.MCP.RegistryRequired = true
	cfg.AssetPolicy.MCP.Default = "deny"

	decision := cfg.EvaluateAssetPolicy(AssetPolicyInput{
		TargetType: "mcp",
		Name:       "rogue",
	})

	if decision.Action != "block" || decision.RawAction != "block" {
		t.Fatalf("decision action=%q raw=%q, want block/block", decision.Action, decision.RawAction)
	}
	if decision.Source != "registry-required-empty" {
		t.Fatalf("source=%q, want registry-required-empty (the empty-registry guard takes precedence over default-deny so operators can distinguish the two failure modes)", decision.Source)
	}
}

func TestNormalizeRegistryEmptyActionDefaultsToDeny(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  string
	}{
		{"", registryEmptyActionDeny},
		{"deny", registryEmptyActionDeny},
		{"DENY", registryEmptyActionDeny},
		{"block", registryEmptyActionDeny},
		{"allow", registryEmptyActionAllow},
		{"ALLOW", registryEmptyActionAllow},
		{"unsupported-value", registryEmptyActionDeny},
	} {
		if got := normalizeRegistryEmptyAction(tc.input); got != tc.want {
			t.Errorf("normalizeRegistryEmptyAction(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestEvaluateAssetPolicyRegistryMatchAllows(t *testing.T) {
	cfg := &Config{AssetPolicy: DefaultAssetPolicy()}
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = AssetPolicyModeAction
	cfg.AssetPolicy.MCP.RegistryRequired = true
	cfg.AssetPolicy.MCP.Registry = []AssetPolicyRule{{
		Name:       "filesystem",
		Command:    "mcp-server-filesystem",
		ArgsPrefix: []string{"/workspace"},
	}}

	decision := cfg.EvaluateAssetPolicy(AssetPolicyInput{
		TargetType: "mcp",
		Name:       "filesystem",
		Command:    "/usr/local/bin/mcp-server-filesystem",
		Args:       []string{"/workspace", "--read-only"},
	})

	if decision.Action != "allow" || decision.RawAction != "allow" {
		t.Fatalf("decision action=%q raw=%q, want allow/allow", decision.Action, decision.RawAction)
	}
	if decision.Source != "registry" {
		t.Fatalf("source=%q, want registry", decision.Source)
	}
	if decision.RegistryStatus != "registered" {
		t.Fatalf("registry_status=%q, want registered", decision.RegistryStatus)
	}
}
