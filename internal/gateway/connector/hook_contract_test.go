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
		{"codex_known", "codex", "codex 0.31.0", HookCompatibilityKnown, "codex-hooks-v1", "0.31.0"},
		{"codex_unknown_future_major", "codex", "codex 1.2.0", HookCompatibilityUnknown, "", "1.2.0"},
		{"claude_alias_known", "claude-code", "Claude Code v1.0.55", HookCompatibilityKnown, "claudecode-hooks-v1", "1.0.55"},
		{"unversioned_uses_default", "cursor", "", HookCompatibilityUnversioned, "cursor-hooks-v1", ""},
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

func TestApplyHookContractPinsProfileCapabilities(t *testing.T) {
	profile := NewClaudeCodeConnector().HookProfile(SetupOpts{
		APIAddr:      "127.0.0.1:18970",
		AgentVersion: "Claude Code v1.0.55",
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
