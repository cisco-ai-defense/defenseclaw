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
