// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestHookContractResolution(t *testing.T) {
	cases := []struct {
		name       string
		connector  string
		version    string
		wantStatus string
		wantID     string
		wantNorm   string
	}{
		{"codex_known", "codex", "codex 0.124.0", HookCompatibilityKnown, "codex-hooks-v1", "0.124.0"},
		{"codex_unknown_before_stable", "codex", "codex 0.123.0", HookCompatibilityUnknown, "", "0.123.0"},
		{"claude_alias_known", "claude-code", "Claude Code v2.1.144", HookCompatibilityKnown, "claudecode-hooks-v1", "2.1.144"},
		{"unversioned_uses_default", "cursor", "", HookCompatibilityUnversioned, "cursor-hooks-v1", ""},
		{"openclaw_proxy_not_gated", "openclaw", "", HookCompatibilityNotGated, "", ""},
		{"zeptoclaw_proxy_not_gated", "zeptoclaw", "zeptoclaw 0.5.0", HookCompatibilityNotGated, "", "0.5.0"},
		{"bad_version_unknown", "codex", "codex nightly", HookCompatibilityUnknown, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ResolveHookContract(tc.connector, tc.version)
			if got.Status != tc.wantStatus {
				t.Fatalf("Status=%q want %q (%+v)", got.Status, tc.wantStatus, got)
			}
			if got.Contract.ContractID != tc.wantID {
				t.Fatalf("ContractID=%q want %q", got.Contract.ContractID, tc.wantID)
			}
			if got.NormalizedVersion != tc.wantNorm {
				t.Fatalf("NormalizedVersion=%q want %q", got.NormalizedVersion, tc.wantNorm)
			}
		})
	}
}

func TestHookContractsCoverHookEndpoints(t *testing.T) {
	reg := NewDefaultRegistry()
	for _, name := range []string{"codex", "claudecode", "hermes", "cursor", "windsurf", "geminicli", "copilot"} {
		conn, ok := reg.Get(name)
		if !ok {
			t.Fatalf("registry missing %s", name)
		}
		if _, ok := conn.(HookEndpoint); !ok {
			t.Fatalf("%s must expose HookEndpoint", name)
		}
		contracts := KnownHookContracts(name)
		if len(contracts) == 0 {
			t.Fatalf("%s has no hook contracts", name)
		}
		for _, contract := range contracts {
			if contract.ContractID == "" {
				t.Fatalf("%s contract missing id", name)
			}
			if len(contract.Events) == 0 {
				t.Fatalf("%s contract %s missing events", name, contract.ContractID)
			}
			if len(contract.AIDSurfaces) == 0 {
				t.Fatalf("%s contract %s missing AID surfaces", name, contract.ContractID)
			}
			if contract.ResponseFieldName == "" {
				t.Fatalf("%s contract %s missing response field", name, contract.ContractID)
			}
		}
	}
}

func TestHookContractsManifestMatchesRuntime(t *testing.T) {
	type manifestContract struct {
		ContractID   string `json:"contract_id"`
		AgentVersion struct {
			MinInclusive string `json:"min_inclusive"`
			MaxExclusive string `json:"max_exclusive"`
		} `json:"agent_version"`
		DefaultForUnversioned bool     `json:"default_for_unversioned"`
		HookScriptVersion     string   `json:"hook_script_version"`
		ResponseField         string   `json:"response_field"`
		Events                []string `json:"events"`
		AIDSurfaces           []string `json:"aid_surfaces"`
		SupportsTraceparent   bool     `json:"supports_traceparent"`
		NativeOTLP            bool     `json:"native_otlp"`
		Capabilities          struct {
			CanBlock           bool     `json:"can_block"`
			CanAskNative       bool     `json:"can_ask_native"`
			AskEvents          []string `json:"ask_events"`
			BlockEvents        []string `json:"block_events"`
			SupportsFailClosed bool     `json:"supports_fail_closed"`
			Scope              string   `json:"scope"`
		} `json:"capabilities"`
	}
	type manifestConnector struct {
		Kind              string             `json:"kind"`
		CompatibilityGate string             `json:"compatibility_gate"`
		Contracts         []manifestContract `json:"contracts"`
	}
	type manifest struct {
		Connectors map[string]manifestConnector `json:"connectors"`
	}

	path := filepath.Join("..", "..", "..", "cli", "defenseclaw", "inventory", "hook_contracts.json")
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read hook contract manifest: %v", err)
	}
	var gotManifest manifest
	if err := json.Unmarshal(payload, &gotManifest); err != nil {
		t.Fatalf("unmarshal hook contract manifest: %v", err)
	}

	for _, proxy := range []string{"openclaw", "zeptoclaw"} {
		spec, ok := gotManifest.Connectors[proxy]
		if !ok {
			t.Fatalf("manifest missing proxy connector %s", proxy)
		}
		if spec.CompatibilityGate != "not-gated" {
			t.Fatalf("%s compatibility_gate=%q want not-gated", proxy, spec.CompatibilityGate)
		}
		if len(spec.Contracts) != 0 {
			t.Fatalf("%s should not publish hook contracts in manifest", proxy)
		}
		resolution := ResolveHookContract(proxy, "")
		if resolution.Status != HookCompatibilityNotGated {
			t.Fatalf("%s runtime status=%q want %q", proxy, resolution.Status, HookCompatibilityNotGated)
		}
		if resolution.Contract.ContractID != "" {
			t.Fatalf("%s should not resolve a runtime hook contract", proxy)
		}
	}

	for name, runtimeContracts := range builtinHookContracts {
		spec, ok := gotManifest.Connectors[name]
		if !ok {
			t.Fatalf("manifest missing hook connector %s", name)
		}
		if spec.Kind != "hook" || spec.CompatibilityGate != "hook-contract" {
			t.Fatalf("%s manifest kind/gate drifted: %+v", name, spec)
		}
		if len(spec.Contracts) != len(runtimeContracts) {
			t.Fatalf("%s manifest contract count=%d want %d", name, len(spec.Contracts), len(runtimeContracts))
		}
		byID := make(map[string]manifestContract, len(spec.Contracts))
		for _, contract := range spec.Contracts {
			byID[contract.ContractID] = contract
		}
		for _, runtime := range runtimeContracts {
			manifestContract, ok := byID[runtime.ContractID]
			if !ok {
				t.Fatalf("%s manifest missing contract %s", name, runtime.ContractID)
			}
			if manifestContract.AgentVersion.MinInclusive != runtime.MinAgentVersion {
				t.Fatalf("%s min version=%q want %q", runtime.ContractID, manifestContract.AgentVersion.MinInclusive, runtime.MinAgentVersion)
			}
			if manifestContract.AgentVersion.MaxExclusive != runtime.MaxAgentVersion {
				t.Fatalf("%s max version=%q want %q", runtime.ContractID, manifestContract.AgentVersion.MaxExclusive, runtime.MaxAgentVersion)
			}
			if manifestContract.DefaultForUnversioned != runtime.DefaultForUnversioned {
				t.Fatalf("%s default_for_unversioned=%v want %v", runtime.ContractID, manifestContract.DefaultForUnversioned, runtime.DefaultForUnversioned)
			}
			if manifestContract.HookScriptVersion != runtime.HookScriptVersion {
				t.Fatalf("%s hook script version=%q want %q", runtime.ContractID, manifestContract.HookScriptVersion, runtime.HookScriptVersion)
			}
			if manifestContract.ResponseField != runtime.ResponseFieldName {
				t.Fatalf("%s response field=%q want %q", runtime.ContractID, manifestContract.ResponseField, runtime.ResponseFieldName)
			}
			if !sameStrings(manifestContract.Events, runtime.Events) {
				t.Fatalf("%s events=%v want %v", runtime.ContractID, manifestContract.Events, runtime.Events)
			}
			if !sameStrings(manifestContract.AIDSurfaces, runtime.AIDSurfaces) {
				t.Fatalf("%s aid_surfaces=%v want %v", runtime.ContractID, manifestContract.AIDSurfaces, runtime.AIDSurfaces)
			}
			if manifestContract.SupportsTraceparent != runtime.SupportsTraceparent {
				t.Fatalf("%s traceparent=%v want %v", runtime.ContractID, manifestContract.SupportsTraceparent, runtime.SupportsTraceparent)
			}
			if manifestContract.NativeOTLP != runtime.NativeOTLP {
				t.Fatalf("%s native_otlp=%v want %v", runtime.ContractID, manifestContract.NativeOTLP, runtime.NativeOTLP)
			}
			if manifestContract.Capabilities.CanBlock != runtime.Capabilities.CanBlock {
				t.Fatalf("%s can_block=%v want %v", runtime.ContractID, manifestContract.Capabilities.CanBlock, runtime.Capabilities.CanBlock)
			}
			if manifestContract.Capabilities.CanAskNative != runtime.Capabilities.CanAskNative {
				t.Fatalf("%s can_ask_native=%v want %v", runtime.ContractID, manifestContract.Capabilities.CanAskNative, runtime.Capabilities.CanAskNative)
			}
			if !sameStrings(manifestContract.Capabilities.AskEvents, runtime.Capabilities.AskEvents) {
				t.Fatalf("%s ask_events=%v want %v", runtime.ContractID, manifestContract.Capabilities.AskEvents, runtime.Capabilities.AskEvents)
			}
			if !sameStrings(manifestContract.Capabilities.BlockEvents, runtime.Capabilities.BlockEvents) {
				t.Fatalf("%s block_events=%v want %v", runtime.ContractID, manifestContract.Capabilities.BlockEvents, runtime.Capabilities.BlockEvents)
			}
			if manifestContract.Capabilities.SupportsFailClosed != runtime.Capabilities.SupportsFailClosed {
				t.Fatalf("%s supports_fail_closed=%v want %v", runtime.ContractID, manifestContract.Capabilities.SupportsFailClosed, runtime.Capabilities.SupportsFailClosed)
			}
			if manifestContract.Capabilities.Scope != runtime.Capabilities.Scope {
				t.Fatalf("%s scope=%q want %q", runtime.ContractID, manifestContract.Capabilities.Scope, runtime.Capabilities.Scope)
			}
		}
	}
}

func TestUnversionedResolutionUsesDefaultMarker(t *testing.T) {
	const connectorName = "testdefault"
	previous, hadPrevious := builtinHookContracts[connectorName]
	t.Cleanup(func() {
		if hadPrevious {
			builtinHookContracts[connectorName] = previous
		} else {
			delete(builtinHookContracts, connectorName)
		}
	})
	builtinHookContracts[connectorName] = []HookContract{
		{
			Connector:         connectorName,
			ContractID:        "test-hooks-v1",
			MinAgentVersion:   "1.0.0",
			HookScriptVersion: "v1",
		},
		{
			Connector:             connectorName,
			ContractID:            "test-hooks-v2",
			MinAgentVersion:       "2.0.0",
			DefaultForUnversioned: true,
			HookScriptVersion:     "v2",
		},
	}

	got := ResolveHookContract(connectorName, "")
	if got.Status != HookCompatibilityUnversioned {
		t.Fatalf("Status=%q want %q", got.Status, HookCompatibilityUnversioned)
	}
	if got.Contract.ContractID != "test-hooks-v2" {
		t.Fatalf("ContractID=%q want test-hooks-v2", got.Contract.ContractID)
	}
}

func sameStrings(a, b []string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return reflect.DeepEqual(a, b)
}

func TestApplyHookContractPinsProfileCapabilities(t *testing.T) {
	profile := NewClaudeCodeConnector().HookProfile(SetupOpts{
		APIAddr:      "127.0.0.1:18970",
		AgentVersion: "Claude Code v2.1.144",
	})
	if profile.ContractID != "claudecode-hooks-v1" {
		t.Fatalf("ContractID=%q", profile.ContractID)
	}
	if profile.CompatibilityStatus != HookCompatibilityKnown {
		t.Fatalf("CompatibilityStatus=%q", profile.CompatibilityStatus)
	}
	if !profile.Capabilities.CanAskNative || len(profile.Capabilities.AskEvents) != 1 || profile.Capabilities.AskEvents[0] != "PreToolUse" {
		t.Fatalf("Claude Code ask capabilities drifted: %+v", profile.Capabilities)
	}
	if !HookProfileAIDSurfaceEnabled(profile, "tool_call") {
		t.Fatalf("AID tool_call surface not enabled: %+v", profile.AIDSurfaces)
	}
}

func TestApplyHookContractUsesPinnedContractForUnknownVersion(t *testing.T) {
	profile := NewCodexConnector().HookProfile(SetupOpts{
		APIAddr:        "127.0.0.1:18970",
		AgentVersion:   "codex nightly",
		HookContractID: "codex-hooks-v1",
	})
	if profile.ContractID != "codex-hooks-v1" {
		t.Fatalf("ContractID=%q", profile.ContractID)
	}
	if profile.CompatibilityStatus != HookCompatibilityUnknown {
		t.Fatalf("CompatibilityStatus=%q", profile.CompatibilityStatus)
	}
	if profile.ResponseFieldName != "codex_output" {
		t.Fatalf("ResponseFieldName=%q", profile.ResponseFieldName)
	}
	if !profile.Capabilities.CanBlock || len(profile.SupportedEvents) == 0 {
		t.Fatalf("pinned contract did not populate capabilities/events: %+v", profile)
	}
}

func TestHookContractLockSaveLoadAndDrift(t *testing.T) {
	dir := t.TempDir()
	conn := NewHermesConnector()
	opts := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:18970"}
	if err := WriteHookScriptsForConnectorObjectWithOpts(filepath.Join(dir, "hooks"), opts, conn); err != nil {
		t.Fatalf("write hooks: %v", err)
	}
	entry := NewHookContractLockEntry(opts, conn, "test-build")
	if entry.ContractID != "hermes-hooks-v1" {
		t.Fatalf("ContractID=%q", entry.ContractID)
	}
	if len(entry.HookScriptDigests) == 0 {
		t.Fatalf("expected hook script digests")
	}
	if err := SaveHookContractLockEntry(dir, entry); err != nil {
		t.Fatalf("save lock: %v", err)
	}
	loaded := LoadHookContractLockEntry(dir, "hermes")
	if loaded.ContractID != entry.ContractID {
		t.Fatalf("loaded ContractID=%q want %q", loaded.ContractID, entry.ContractID)
	}
	changed := loaded
	changed.ContractID = "hermes-hooks-v2"
	if !HookContractLockDrifted(loaded, changed) {
		t.Fatalf("contract change should be drift")
	}
}

func TestHookContractLockEntryUsesPinnedContractMetadata(t *testing.T) {
	dir := t.TempDir()
	conn := NewCodexConnector()
	opts := SetupOpts{
		DataDir:        dir,
		APIAddr:        "127.0.0.1:18970",
		AgentVersion:   "codex nightly",
		HookContractID: "codex-hooks-v1",
	}
	if err := WriteHookScriptsForConnectorObjectWithOpts(filepath.Join(dir, "hooks"), opts, conn); err != nil {
		t.Fatalf("write hooks: %v", err)
	}
	entry := NewHookContractLockEntry(opts, conn, "test-build")
	if entry.ContractID != "codex-hooks-v1" {
		t.Fatalf("ContractID=%q", entry.ContractID)
	}
	if entry.HookScriptVersion != "v6" {
		t.Fatalf("HookScriptVersion=%q", entry.HookScriptVersion)
	}
	if entry.CompatibilityStatus != HookCompatibilityUnknown {
		t.Fatalf("CompatibilityStatus=%q", entry.CompatibilityStatus)
	}
}

func TestLoadCachedAgentVersion(t *testing.T) {
	dir := t.TempDir()
	payload := map[string]interface{}{
		"version": 1,
		"agents": map[string]interface{}{
			"codex": map[string]interface{}{"version": "codex 0.31.0"},
		},
	}
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "agent_discovery.json"), b, 0o600); err != nil {
		t.Fatalf("write discovery: %v", err)
	}
	if got := LoadCachedAgentVersion(dir, "codex"); got != "codex 0.31.0" {
		t.Fatalf("LoadCachedAgentVersion=%q", got)
	}
}
