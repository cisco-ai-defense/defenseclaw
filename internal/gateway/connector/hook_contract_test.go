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
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func sharedHookBytes(t *testing.T, hookDir string) map[string][]byte {
	t.Helper()
	out := make(map[string][]byte, len(genericHookScripts)+len(hookHelperScripts))
	for _, name := range append(append([]string{}, genericHookScripts...), hookHelperScripts...) {
		body, err := os.ReadFile(filepath.Join(hookDir, name))
		if err != nil {
			t.Fatalf("read shared hook %s: %v", name, err)
		}
		out[name] = body
	}
	return out
}

func TestHookContractResolution(t *testing.T) {
	cases := []struct {
		name       string
		connector  string
		version    string
		wantStatus string
		wantID     string
		wantNorm   string
	}{
		{"codex_six_event_minimum", "codex", "codex 0.124.0", HookCompatibilityKnown, "codex-hooks-v1", "0.124.0"},
		{"codex_six_event_upper_boundary", "codex", "codex 0.128.99", HookCompatibilityKnown, "codex-hooks-v1", "0.128.99"},
		{"codex_eight_event_minimum", "codex", "codex 0.129.0", HookCompatibilityKnown, "codex-hooks-v2", "0.129.0"},
		{"codex_eight_event_upper_boundary", "codex", "codex 0.132.99", HookCompatibilityKnown, "codex-hooks-v2", "0.132.99"},
		{"codex_ten_event_minimum", "codex", "codex 0.133.0", HookCompatibilityKnown, "codex-hooks-v3", "0.133.0"},
		{"codex_current", "codex", "codex 0.144.3", HookCompatibilityKnown, "codex-hooks-v3", "0.144.3"},
		{"codex_unversioned_uses_full_default", "codex", "", HookCompatibilityUnversioned, "codex-hooks-v3", ""},
		{"codex_unknown_before_stable", "codex", "codex 0.123.0", HookCompatibilityUnknown, "", "0.123.0"},
		{"claude_before_message_display", "claude-code", "Claude Code v2.1.151", HookCompatibilityUnknown, "", "2.1.151"},
		{"claude_alias_known", "claude-code", "Claude Code v2.1.152", HookCompatibilityKnown, "claudecode-hooks-v1", "2.1.152"},
		{"openhands_alias_known", "open-hands", "OpenHands 1.0.0", HookCompatibilityKnown, "openhands-hooks-v1", "1.0.0"},
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

func TestCodexHookContractVersionedEventMatrix(t *testing.T) {
	tests := []struct {
		version string
		wantID  string
		events  []string
	}{
		{
			version: "0.124.0",
			wantID:  "codex-hooks-v1",
			events: []string{
				"SessionStart", "UserPromptSubmit", "PreToolUse",
				"PermissionRequest", "PostToolUse", "Stop",
			},
		},
		{
			version: "0.129.0",
			wantID:  "codex-hooks-v2",
			events: []string{
				"SessionStart", "UserPromptSubmit", "PreToolUse",
				"PermissionRequest", "PostToolUse", "PreCompact",
				"PostCompact", "Stop",
			},
		},
		{
			version: "0.133.0",
			wantID:  "codex-hooks-v3",
			events: []string{
				"SessionStart", "UserPromptSubmit", "PreToolUse",
				"PermissionRequest", "PostToolUse", "SubagentStart",
				"SubagentStop", "PreCompact", "PostCompact", "Stop",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.version, func(t *testing.T) {
			resolution := ResolveHookContract("codex", test.version)
			if resolution.Status != HookCompatibilityKnown {
				t.Fatalf("status = %q, want %q", resolution.Status, HookCompatibilityKnown)
			}
			if resolution.Contract.ContractID != test.wantID {
				t.Fatalf("contract = %q, want %q", resolution.Contract.ContractID, test.wantID)
			}
			if !reflect.DeepEqual(resolution.Contract.Events, test.events) {
				t.Fatalf("events = %#v, want %#v", resolution.Contract.Events, test.events)
			}
		})
	}
}

func TestHookContractNeedsActionOverride(t *testing.T) {
	cases := []struct {
		status string
		want   bool
	}{
		{HookCompatibilityKnown, false},
		{HookCompatibilityNotGated, false},
		{HookCompatibilityUnversioned, true},
		{HookCompatibilityUnknown, true},
	}
	for _, tc := range cases {
		t.Run(tc.status, func(t *testing.T) {
			got := HookContractNeedsActionOverride(HookContractResolution{Status: tc.status})
			if got != tc.want {
				t.Fatalf("HookContractNeedsActionOverride(%q)=%v want %v", tc.status, got, tc.want)
			}
		})
	}
}

func TestHookContractsCoverHookEndpoints(t *testing.T) {
	reg := NewDefaultRegistry()
	for _, name := range []string{"codex", "claudecode", "hermes", "cursor", "windsurf", "geminicli", "copilot", "openhands", "antigravity", "opencode", "omnigent"} {
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
			if contract.ResponseFieldName == "" && name != "omnigent" {
				t.Fatalf("%s contract %s missing response field", name, contract.ContractID)
			}
			if name == "omnigent" && contract.ResponseFieldName != "" {
				t.Fatalf("%s contract %s must return its policy verdict directly, not through %q", name, contract.ContractID, contract.ResponseFieldName)
			}
		}
	}
}

// TestContentEnvelopeKeyDeclarations pins which connectors declare a
// content envelope: hermes nests inspectable content under the
// per-event "extra" object; every other contract is flat (and must
// stay declared-empty so the generic decoder never opens an undeclared
// sub-object). ApplyHookContract must copy the declaration onto the
// resolved profile so the gateway decoder can read it.
func TestContentEnvelopeKeyDeclarations(t *testing.T) {
	for name, contracts := range builtinHookContracts {
		for _, contract := range contracts {
			want := ""
			if name == "hermes" {
				want = "extra"
			}
			if contract.ContentEnvelopeKey != want {
				t.Errorf("%s %s ContentEnvelopeKey=%q want %q", name, contract.ContractID, contract.ContentEnvelopeKey, want)
			}
		}
	}
	hermes := NewHermesConnector().HookProfile(SetupOpts{APIAddr: "127.0.0.1:18970"})
	if hermes.ContentEnvelopeKey != "extra" {
		t.Fatalf("hermes profile ContentEnvelopeKey=%q want %q", hermes.ContentEnvelopeKey, "extra")
	}
	cursor := NewCursorConnector().HookProfile(SetupOpts{APIAddr: "127.0.0.1:18970"})
	if cursor.ContentEnvelopeKey != "" {
		t.Fatalf("cursor profile ContentEnvelopeKey=%q want empty", cursor.ContentEnvelopeKey)
	}
}

func TestHookContractsManifestMatchesRuntime(t *testing.T) {
	type manifestContract struct {
		ContractID   string `json:"contract_id"`
		AgentVersion struct {
			MinInclusive string `json:"min_inclusive"`
			MaxExclusive string `json:"max_exclusive"`
		} `json:"agent_version"`
		DefaultForUnversioned   bool     `json:"default_for_unversioned"`
		HookScriptVersion       string   `json:"hook_script_version"`
		HookConfigPathTemplates []string `json:"hook_config_path_templates"`
		ResponseField           string   `json:"response_field"`
		Events                  []string `json:"events"`
		AIDSurfaces             []string `json:"aid_surfaces"`
		SupportsTraceparent     bool     `json:"supports_traceparent"`
		NativeOTLP              bool     `json:"native_otlp"`
		ContentEnvelopeKey      string   `json:"content_envelope_key"`
		Capabilities            struct {
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
			if !sameStrings(manifestContract.HookConfigPathTemplates, runtime.HookConfigPathTemplates) {
				t.Fatalf("%s hook config path templates=%v want %v", runtime.ContractID, manifestContract.HookConfigPathTemplates, runtime.HookConfigPathTemplates)
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
			if manifestContract.ContentEnvelopeKey != runtime.ContentEnvelopeKey {
				t.Fatalf("%s content_envelope_key=%q want %q", runtime.ContractID, manifestContract.ContentEnvelopeKey, runtime.ContentEnvelopeKey)
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

func stringInSlice(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestApplyHookContractPinsProfileCapabilities(t *testing.T) {
	profile := NewClaudeCodeConnector().HookProfile(SetupOpts{
		APIAddr:      "127.0.0.1:18970",
		AgentVersion: "Claude Code v2.1.152",
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
	changed.ContractID = "hermes-hooks-v0-other"
	if !HookContractLockDrifted(loaded, changed) {
		t.Fatalf("contract change should be drift")
	}
}

func TestSaveFreshHookContractLockEntryRefreshesIdempotentEvidence(t *testing.T) {
	dir := testenv.PrivateTempDir(t)
	entry := HookContractLockEntry{Connector: "codex", ContractID: "codex-hooks-v1"}
	if err := SaveHookContractLockEntry(dir, entry); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, hookContractLockFile)
	old := time.Unix(1, 0)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	if err := SaveHookContractLockEntry(dir, entry); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.ModTime().Equal(old) {
		t.Fatal("ordinary idempotent save unexpectedly rewrote the contract lock")
	}
	if err := SaveFreshHookContractLockEntry(dir, entry); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.ModTime().Equal(old) {
		t.Fatal("fresh boot save did not rewrite unchanged contract evidence")
	}
}

func TestSharedInspectScriptsAreConnectorIndependent(t *testing.T) {
	dir := testenv.PrivateTempDir(t)
	hookDir := filepath.Join(dir, "hooks")
	claudeOpts := SetupOpts{
		DataDir:            dir,
		APIAddr:            "127.0.0.1:18970",
		HookFailMode:       "closed",
		HookAPIToken:       "claude-scoped-fixture",
		HookAPITokenScoped: true,
		ManagedEnterprise:  true,
	}
	if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, claudeOpts, NewClaudeCodeConnector()); err != nil {
		t.Fatalf("write Claude hooks: %v", err)
	}
	before := sharedHookBytes(t, hookDir)

	codexOpts := claudeOpts
	codexOpts.HookFailMode = "open"
	codexOpts.HookAPIToken = "codex-scoped-fixture"
	if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, codexOpts, NewCodexConnector()); err != nil {
		t.Fatalf("write Codex hooks: %v", err)
	}
	after := sharedHookBytes(t, hookDir)
	for name, want := range before {
		if !bytes.Equal(after[name], want) {
			t.Fatalf("shared hook %s changed across connector/mode/token render", name)
		}
		for _, forbidden := range [][]byte{
			[]byte(".hook-claudecode.token"),
			[]byte(".hook-codex.token"),
			[]byte("X-DefenseClaw-Connector: claudecode"),
			[]byte("X-DefenseClaw-Connector: codex"),
		} {
			if bytes.Contains(after[name], forbidden) {
				t.Fatalf("shared hook %s contains connector-specific data %q", name, forbidden)
			}
		}
	}
}

func TestHookContractLockStoresSharedScriptsOnce(t *testing.T) {
	dir := testenv.PrivateTempDir(t)
	hookDir := filepath.Join(dir, "hooks")
	connectors := []struct {
		conn Connector
		mode string
	}{
		{NewClaudeCodeConnector(), "closed"},
		{NewCodexConnector(), "open"},
	}
	for _, tc := range connectors {
		opts := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:18970", HookFailMode: tc.mode}
		if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, tc.conn); err != nil {
			t.Fatalf("write %s hooks: %v", tc.conn.Name(), err)
		}
		if err := SaveHookContractLockEntry(dir, NewHookContractLockEntry(opts, tc.conn, "test-build")); err != nil {
			t.Fatalf("save %s lock: %v", tc.conn.Name(), err)
		}
	}
	lock := loadHookContractLock(dir)
	if lock.Version != hookContractLockVersion {
		t.Fatalf("lock version=%d want %d", lock.Version, hookContractLockVersion)
	}
	if len(lock.SharedHookScriptDigests) != len(genericHookScripts)+len(hookHelperScripts) {
		t.Fatalf("shared digests=%v", lock.SharedHookScriptDigests)
	}
	for _, tc := range connectors {
		entry := lock.Connectors[tc.conn.Name()]
		for name := range entry.HookScriptDigests {
			if sharedHookScriptName(name) {
				t.Fatalf("%s entry retained shared digest %s", tc.conn.Name(), name)
			}
		}
		owned := "codex-hook.sh"
		if tc.conn.Name() == "claudecode" {
			owned = "claude-code-hook.sh"
		}
		if entry.HookScriptDigests[owned] == "" {
			t.Fatalf("%s owned digest missing: %v", tc.conn.Name(), entry.HookScriptDigests)
		}
	}
}

func TestHookContractLockMigratesDivergentLegacySharedDigests(t *testing.T) {
	dir := testenv.PrivateTempDir(t)
	hookDir := filepath.Join(dir, "hooks")
	opts := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:18970", HookFailMode: "closed"}
	conn := NewClaudeCodeConnector()
	if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, conn); err != nil {
		t.Fatalf("write canonical hooks: %v", err)
	}
	selected := NewHookContractLockEntry(opts, conn, "test-build")
	peerOwned := "sha256:peer-owned"
	legacy := hookContractLock{
		Version: 1,
		Connectors: map[string]HookContractLockEntry{
			"claudecode": {
				Connector:         "claudecode",
				ContractID:        "claudecode-hooks-v1",
				HookFailMode:      "open",
				HookScriptDigests: map[string]string{"claude-code-hook.sh": "sha256:old-claude"},
			},
			"codex": {
				Connector:         "codex",
				ContractID:        "codex-hooks-v1",
				HookFailMode:      "open",
				HookScriptDigests: map[string]string{"codex-hook.sh": peerOwned},
			},
		},
	}
	for _, name := range append(append([]string{}, genericHookScripts...), hookHelperScripts...) {
		legacy.Connectors["claudecode"].HookScriptDigests[name] = "sha256:legacy-claude"
		legacy.Connectors["codex"].HookScriptDigests[name] = "sha256:legacy-codex"
	}
	body, err := json.MarshalIndent(legacy, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, hookContractLockFile), append(body, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := SaveHookContractLockEntry(dir, selected); err != nil {
		t.Fatalf("migrate lock: %v", err)
	}
	migratedPath := filepath.Join(dir, hookContractLockFile)
	migrated, err := os.ReadFile(migratedPath)
	if err != nil {
		t.Fatal(err)
	}
	lock := loadHookContractLock(dir)
	if lock.Version != hookContractLockVersion {
		t.Fatalf("migrated version=%d", lock.Version)
	}
	if lock.Connectors["codex"].HookFailMode != "open" || lock.Connectors["codex"].HookScriptDigests["codex-hook.sh"] != peerOwned {
		t.Fatalf("peer metadata changed during migration: %+v", lock.Connectors["codex"])
	}
	for name, digest := range lock.SharedHookScriptDigests {
		actual := HookScriptDigests(opts, conn)[name]
		if digest != actual {
			t.Fatalf("shared digest %s=%q want current %q", name, digest, actual)
		}
		for connectorName, entry := range lock.Connectors {
			if _, exists := entry.HookScriptDigests[name]; exists {
				t.Fatalf("legacy shared digest %s remains under %s", name, connectorName)
			}
		}
	}
	if err := SaveHookContractLockEntry(dir, NewHookContractLockEntry(opts, conn, "test-build")); err != nil {
		t.Fatalf("repeat save: %v", err)
	}
	repeated, err := os.ReadFile(migratedPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(repeated, migrated) {
		t.Fatal("repeated reconciliation rewrote an already-current contract lock")
	}
}

func TestHookContractLockRejectsMalformedOrFutureExistingLock(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{name: "malformed", body: `{not-json`},
		{name: "future", body: `{"version":99,"future_field":"preserve","connectors":{"codex":{"connector":"codex"}}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := testenv.PrivateTempDir(t)
			path := filepath.Join(dir, hookContractLockFile)
			before := []byte(tc.body)
			if err := os.WriteFile(path, before, 0o600); err != nil {
				t.Fatal(err)
			}
			err := SaveHookContractLockEntry(dir, HookContractLockEntry{Connector: "claudecode", ContractID: "claudecode-hooks-v1"})
			if err == nil {
				t.Fatal("save accepted an unreadable or unsupported existing lock")
			}
			after, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if !bytes.Equal(after, before) {
				t.Fatal("failed save rewrote existing contract evidence")
			}
		})
	}
}

func TestHookContractLockRejectsPartialSharedDigestSet(t *testing.T) {
	dir := testenv.PrivateTempDir(t)
	entry := HookContractLockEntry{
		Connector:         "claudecode",
		HookScriptDigests: map[string]string{"inspect-tool.sh": "sha256:partial", "claude-code-hook.sh": "sha256:owned"},
	}
	if err := SaveHookContractLockEntry(dir, entry); err == nil {
		t.Fatal("partial shared digest set was accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, hookContractLockFile)); !os.IsNotExist(err) {
		t.Fatalf("partial save created a lock: %v", err)
	}
}

func TestHookContractLockNormalizesSharedLauncherDigestAcrossPeers(t *testing.T) {
	dir := testenv.PrivateTempDir(t)
	legacy := hookContractLock{
		Version: 1,
		Connectors: map[string]HookContractLockEntry{
			"claudecode": {Connector: "claudecode", HookScriptDigests: map[string]string{windowsHookBinaryName: "sha256:old-claude"}},
			"codex":      {Connector: "codex", HookScriptDigests: map[string]string{windowsHookBinaryName: "sha256:old-codex"}},
		},
	}
	body, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, hookContractLockFile), body, 0o600); err != nil {
		t.Fatal(err)
	}
	selected := legacy.Connectors["claudecode"]
	selected.HookScriptDigests[windowsHookBinaryName] = "sha256:current-launcher"
	if err := SaveHookContractLockEntry(dir, selected); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"claudecode", "codex"} {
		entry := LoadHookContractLockEntry(dir, name)
		if got := entry.HookScriptDigests[windowsHookBinaryName]; got != "sha256:current-launcher" {
			t.Fatalf("%s launcher digest=%q", name, got)
		}
	}
}

func TestHookContractClearRollsBackWhenRuntimeStateCannotBeUpdated(t *testing.T) {
	dir := testenv.PrivateTempDir(t)
	hookDir := filepath.Join(dir, "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	lock := hookContractLock{
		Version: hookContractLockVersion,
		SharedHookScriptDigests: map[string]string{
			"inspect-tool.sh": "sha256:shared",
		},
		Connectors: map[string]HookContractLockEntry{
			"claudecode": {Connector: "claudecode"},
			"codex":      {Connector: "codex"},
		},
	}
	body, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	body = append(body, '\n')
	lockPath := filepath.Join(dir, hookContractLockFile)
	if err := os.WriteFile(lockPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hookDir, hookConfigSidecarName), []byte(`{"malformed":`), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := ClearHookContractLockEntry(dir, "claudecode"); err == nil {
		t.Fatal("clear succeeded despite malformed runtime state")
	}
	after, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, body) {
		t.Fatal("failed runtime clear did not restore the contract lock")
	}
}

func TestHookContractClearCannotBeUndoneByStaleReconcileSave(t *testing.T) {
	dir := testenv.PrivateTempDir(t)
	hookDir := filepath.Join(dir, "hooks")
	opts := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:18970", HookFailMode: "closed"}
	conn := NewClaudeCodeConnector()
	if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, conn); err != nil {
		t.Fatal(err)
	}
	entry := NewHookContractLockEntry(opts, conn, "test-build")
	if err := SaveHookContractLockEntry(dir, entry); err != nil {
		t.Fatal(err)
	}
	if err := ClearHookContractLockEntry(dir, conn.Name()); err != nil {
		t.Fatal(err)
	}
	if err := SaveHookContractLockEntry(dir, entry); err == nil {
		t.Fatal("stale reconcile save resurrected a contract after runtime teardown")
	}
	if got := LoadHookContractLockEntry(dir, conn.Name()); got.Connector != "" {
		t.Fatalf("stale reconcile save restored cleared contract: %+v", got)
	}
	if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, conn); err != nil {
		t.Fatal(err)
	}
	if err := SaveHookContractLockEntry(dir, NewHookContractLockEntry(opts, conn, "test-build")); err != nil {
		t.Fatalf("fresh reconcile could not restore runtime and contract together: %v", err)
	}
}

func TestHookContractLockConcurrentUpdatesPreserveConnectorPeers(t *testing.T) {
	dir := testenv.PrivateTempDir(t)
	entries := []HookContractLockEntry{
		{Connector: "claudecode", ContractID: "claudecode-hooks-v1", HookFailMode: "closed"},
		{Connector: "codex", ContractID: "codex-hooks-v1", HookFailMode: "open"},
	}
	var wg sync.WaitGroup
	errors := make(chan error, len(entries))
	for _, entry := range entries {
		entry := entry
		wg.Add(1)
		go func() {
			defer wg.Done()
			errors <- SaveHookContractLockEntry(dir, entry)
		}()
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, entry := range entries {
		loaded := LoadHookContractLockEntry(dir, entry.Connector)
		if loaded.ContractID != entry.ContractID || loaded.HookFailMode != entry.HookFailMode {
			t.Fatalf("connector %s lock entry lost during concurrent update: %+v", entry.Connector, loaded)
		}
	}
}

func TestHookContractDriftExcludesGeneratedArtifactChanges(t *testing.T) {
	previous := HookContractLockEntry{
		Connector:              "codex",
		RawAgentVersion:        "codex-cli 0.142.4",
		NormalizedAgentVersion: "0.142.4",
		ContractID:             "codex-hooks-v1",
		HookScriptDigests:      map[string]string{"codex-hook.sh": "sha256:old"},
	}
	current := previous
	current.HookScriptDigests = map[string]string{"codex-hook.sh": "sha256:new"}

	if HookContractLockDrifted(previous, current) {
		t.Fatal("generated artifact drift must remain repairable")
	}
	if HookContractCompatibilityDrifted(previous, current) {
		t.Fatal("generated artifact drift must not be treated as upstream contract drift")
	}

	current = previous
	current.ContractID = "codex-hooks-v2"
	if !HookContractCompatibilityDrifted(previous, current) {
		t.Fatal("contract identity changes must remain compatibility drift")
	}
	if !HookContractLockDrifted(previous, current) {
		t.Fatal("contract identity changes must remain lock drift")
	}

	current = previous
	current.NormalizedAgentVersion = "0.150.0"
	if !HookContractCompatibilityDrifted(previous, current) {
		t.Fatal("agent version changes must remain compatibility drift")
	}
	if !HookContractLockDrifted(previous, current) {
		t.Fatal("agent version changes must remain lock drift")
	}
}

func TestHookContractLockEntryIncludesResolvedLocations(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	workspace := filepath.Join(dir, "repo")
	testenv.SetHome(t, home)
	conn := NewOpenHandsConnector()
	opts := SetupOpts{
		DataDir:      filepath.Join(dir, "dc"),
		APIAddr:      "127.0.0.1:18970",
		WorkspaceDir: workspace,
	}

	entry := NewHookContractLockEntry(opts, conn, "test-build")
	if entry.Locations.WorkspaceDir != workspace {
		t.Fatalf("WorkspaceDir=%q want %q", entry.Locations.WorkspaceDir, workspace)
	}
	if !sameStrings(entry.Locations.HookConfigPaths, []string{filepath.Join(workspace, ".openhands", "hooks.json")}) {
		t.Fatalf("HookConfigPaths=%v", entry.Locations.HookConfigPaths)
	}
	if !stringInSlice(entry.Locations.HookScriptPaths, filepath.Join(opts.DataDir, "hooks", "openhands-hook.sh")) {
		t.Fatalf("HookScriptPaths=%v", entry.Locations.HookScriptPaths)
	}
	if got := entry.Locations.Surfaces["mcp"].ConfigPaths; !sameStrings(got, []string{filepath.Join(home, ".openhands", "mcp.json")}) {
		t.Fatalf("mcp config paths=%v", got)
	}
	if got := entry.Locations.Surfaces["skills"].WritePaths; !sameStrings(got, []string{filepath.Join(workspace, ".agents", "skills")}) {
		t.Fatalf("skill write paths=%v", got)
	}
	skillReads := entry.Locations.Surfaces["skills"].ReadPaths
	for _, want := range []string{
		filepath.Join(workspace, ".agents", "skills"),
		filepath.Join(home, ".agents", "skills"),
		filepath.Join(home, ".openhands", "skills", "installed"),
		filepath.Join(home, ".openhands", "cache", "skills", "public-skills", "skills"),
	} {
		if !stringInSlice(skillReads, want) {
			t.Fatalf("skill read paths=%v missing %q", skillReads, want)
		}
	}
	if entry.Locations.Surfaces["plugins"].Supported {
		t.Fatalf("OpenHands plugins should be recorded as unsupported: %+v", entry.Locations.Surfaces["plugins"])
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

func TestCodexGenericDiscoveryCacheAuthorityIsWindowsScoped(t *testing.T) {
	dir := testenv.PrivateTempDir(t)
	payload := map[string]interface{}{
		"version": 3,
		"agents": map[string]interface{}{
			"codex": map[string]interface{}{
				"installed":   true,
				"version":     "codex 0.31.0",
				"binary_path": `C:\Program Files\Codex\codex.exe`,
				"error":       "",
			},
		},
	}
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := atomicWriteFile(filepath.Join(dir, "agent_discovery.json"), b, 0o600); err != nil {
		t.Fatalf("write discovery: %v", err)
	}
	version := LoadCachedAgentVersion(dir, "codex")
	executable := LoadCachedAgentExecutable(dir, "codex")
	if runtime.GOOS == "windows" {
		if version != "" || executable != "" {
			t.Fatalf("Windows trusted generic cache: version=%q executable=%q", version, executable)
		}
		return
	}
	if version != "codex 0.31.0" || executable != `C:\Program Files\Codex\codex.exe` {
		t.Fatalf("non-Windows discovery parity: version=%q executable=%q", version, executable)
	}
}

func TestCodexSetupSelectionReceiptIsBoundAndSealed(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("protected Codex setup selections are native-Windows authority")
	}
	dir := testenv.PrivateTempDir(t)
	executable := filepath.Join(dir, "codex.exe")
	if err := atomicWriteFile(executable, []byte("fixture-codex-binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	_, digest, ok := setupSelectedAgentExecutableEvidence(executable)
	if !ok {
		t.Fatal("could not hash fixture executable")
	}
	now := time.Now().UTC().Truncate(time.Second)
	receipt := agentSelectionReceipt{
		SchemaVersion: agentSelectionSchemaVersion,
		UpdatedAt:     now.Format(time.RFC3339),
		Selections: map[string]agentSelectionEvidence{
			"codex": {
				Connector:         "codex",
				Source:            "setup-selected",
				Executable:        executable,
				RawVersion:        "codex 0.144.3",
				NormalizedVersion: "0.144.3",
				SHA256:            digest,
				SelectedAt:        now.Format(time.RFC3339),
				ExpiresAt:         now.Add(agentSelectionMaxLifetime).Format(time.RFC3339),
			},
		},
	}
	body, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(filepath.Join(dir, agentSelectionFile), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := LoadCachedAgentVersion(dir, "codex"); got != "codex 0.144.3" {
		t.Fatalf("receipt version = %q", got)
	}
	if got := LoadCachedAgentExecutable(dir, "codex"); !sameCodexExecutablePath(got, executable) {
		t.Fatalf("receipt executable = %q, want %q", got, executable)
	}

	entry := NewHookContractLockEntry(
		SetupOpts{DataDir: dir, AgentVersion: "codex 0.144.3", AgentExecutable: executable},
		NewCodexConnector(),
		"test-build",
	)
	if entry.AgentExecutableSource != "setup-selected" ||
		!sameCodexExecutablePath(entry.AgentExecutable, executable) ||
		entry.AgentExecutableSHA256 != digest {
		t.Fatalf("sealed executable evidence = %+v", entry)
	}
}

func writeCodexSetupSelectionForTest(
	t *testing.T,
	dir string,
	executable string,
	rawVersion string,
	normalizedVersion string,
	selectedAt time.Time,
	expiresAt time.Time,
) agentSelectionEvidence {
	t.Helper()
	_, digest, ok := setupSelectedAgentExecutableEvidence(executable)
	if !ok {
		t.Fatal("could not hash fixture Codex executable")
	}
	selection := agentSelectionEvidence{
		Connector:         "codex",
		Source:            "setup-selected",
		Executable:        executable,
		RawVersion:        rawVersion,
		NormalizedVersion: normalizedVersion,
		SHA256:            digest,
		SelectedAt:        selectedAt.Format(time.RFC3339),
		ExpiresAt:         expiresAt.Format(time.RFC3339),
	}
	receipt := agentSelectionReceipt{
		SchemaVersion: agentSelectionSchemaVersion,
		UpdatedAt:     selectedAt.Format(time.RFC3339),
		Selections:    map[string]agentSelectionEvidence{"codex": selection},
	}
	body, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(filepath.Join(dir, agentSelectionFile), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return selection
}

func writeCodexContractLockForTest(
	t *testing.T,
	dir string,
	entry HookContractLockEntry,
	updatedAt time.Time,
) {
	t.Helper()
	entry.UpdatedAt = updatedAt.Format(time.RFC3339)
	lock := hookContractLock{
		Version:    hookContractLockVersion,
		UpdatedAt:  updatedAt.Format(time.RFC3339),
		Connectors: map[string]HookContractLockEntry{"codex": entry},
	}
	body, err := json.Marshal(lock)
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(filepath.Join(dir, hookContractLockFile), body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestFreshCodexSetupSelectionRepairsLegacyLockAndBecomesAuthoritative(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("protected Codex setup selections are native-Windows authority")
	}
	dir := testenv.PrivateTempDir(t)
	executable := filepath.Join(dir, "codex.exe")
	if err := atomicWriteFile(executable, []byte("replacement-codex-binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	writeCodexContractLockForTest(t, dir, HookContractLockEntry{
		Connector:              "codex",
		RawAgentVersion:        "codex-cli 0.144.0-alpha.4",
		NormalizedAgentVersion: "0.144.0",
		ContractID:             "codex-hooks-v3",
		CompatibilityStatus:    HookCompatibilityKnown,
	}, now.Add(-time.Minute))
	selection := writeCodexSetupSelectionForTest(
		t, dir, executable, "codex-cli 0.144.3", "0.144.3", now, now.Add(agentSelectionMaxLifetime),
	)

	if previous := LoadHookContractLockEntry(dir, "codex"); previous.Connector != "" {
		t.Fatalf("fresh explicit repair exposed stale lock to drift gate: %+v", previous)
	}
	if got := LoadCachedAgentVersion(dir, "codex"); got != selection.RawVersion {
		t.Fatalf("repair version = %q, want %q", got, selection.RawVersion)
	}
	if got := LoadCachedAgentExecutable(dir, "codex"); !sameCodexExecutablePath(got, executable) {
		t.Fatalf("repair executable = %q, want %q", got, executable)
	}
	opts := SetupOpts{DataDir: dir, AgentVersion: selection.RawVersion, AgentExecutable: executable}
	if _, err := validateCodexPolicyExecutable(opts); err != nil {
		t.Fatalf("fresh explicit repair evidence failed policy validation: %v", err)
	}

	entry := NewHookContractLockEntry(opts, NewCodexConnector(), "test-build")
	if err := SaveFreshHookContractLockEntry(dir, entry); err != nil {
		t.Fatalf("persist repaired Codex lock: %v", err)
	}
	sealed := LoadHookContractLockEntry(dir, "codex")
	if !validCodexAgentExecutableEvidence(sealed) ||
		sealed.RawAgentVersion != selection.RawVersion ||
		!sameCodexExecutablePath(sealed.AgentExecutable, executable) ||
		sealed.AgentExecutableSHA256 != selection.SHA256 {
		t.Fatalf("repaired lock did not regain authority: %+v", sealed)
	}
}

func TestNewerCodexSetupSelectionSupersedesOlderValidLock(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("protected Codex setup selections are native-Windows authority")
	}
	dir := testenv.PrivateTempDir(t)
	now := time.Now().UTC().Truncate(time.Second)

	lockedExecutable := filepath.Join(dir, "old", "codex.exe")
	if err := os.MkdirAll(filepath.Dir(lockedExecutable), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(lockedExecutable, []byte("old-locked-codex-binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	locked := NewHookContractLockEntry(
		SetupOpts{
			DataDir:         dir,
			AgentVersion:    "codex-cli 0.144.0-alpha.4",
			AgentExecutable: lockedExecutable,
		},
		NewCodexConnector(),
		"old-build",
	)
	writeCodexContractLockForTest(t, dir, locked, now.Add(-2*time.Minute))

	selectedExecutable := filepath.Join(dir, "current", "codex.exe")
	if err := os.MkdirAll(filepath.Dir(selectedExecutable), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(selectedExecutable, []byte("current-selected-codex-binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	selection := writeCodexSetupSelectionForTest(
		t,
		dir,
		selectedExecutable,
		"codex-cli 0.144.3",
		"0.144.3",
		now,
		now.Add(agentSelectionMaxLifetime),
	)

	if previous := LoadHookContractLockEntry(dir, "codex"); previous.Connector != "" {
		t.Fatalf("newer explicit selection did not supersede older valid lock: %+v", previous)
	}
	if got := LoadCachedAgentVersion(dir, "codex"); got != selection.RawVersion {
		t.Fatalf("selected version = %q, want %q", got, selection.RawVersion)
	}
	if got := LoadCachedAgentExecutable(dir, "codex"); !sameCodexExecutablePath(got, selectedExecutable) {
		t.Fatalf("selected executable = %q, want %q", got, selectedExecutable)
	}
	if _, err := validateCodexPolicyExecutable(SetupOpts{
		DataDir:         dir,
		AgentVersion:    selection.RawVersion,
		AgentExecutable: selectedExecutable,
	}); err != nil {
		t.Fatalf("newer explicit selection failed policy validation: %v", err)
	}
}

func TestNewerCodexLockRejectsStaleSetupSelection(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("protected Codex setup selections are native-Windows authority")
	}
	dir := testenv.PrivateTempDir(t)
	lockedExecutable := filepath.Join(dir, "codex.exe")
	if err := atomicWriteFile(lockedExecutable, []byte("authoritative-codex-binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	locked := NewHookContractLockEntry(
		SetupOpts{DataDir: dir, AgentVersion: "codex-cli 0.144.3", AgentExecutable: lockedExecutable},
		NewCodexConnector(),
		"test-build",
	)
	writeCodexContractLockForTest(t, dir, locked, now.Add(-time.Minute))

	staleExecutable := filepath.Join(dir, "stale", "codex.exe")
	if err := os.MkdirAll(filepath.Dir(staleExecutable), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(staleExecutable, []byte("stale-codex-binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeCodexSetupSelectionForTest(
		t,
		dir,
		staleExecutable,
		"codex-cli 0.144.0-alpha.4",
		"0.144.0",
		now.Add(-2*time.Minute),
		now.Add(5*time.Minute),
	)

	if got := LoadCachedAgentVersion(dir, "codex"); got != locked.RawAgentVersion {
		t.Fatalf("stale receipt replaced newer lock version: %q", got)
	}
	if got := LoadCachedAgentExecutable(dir, "codex"); !sameCodexExecutablePath(got, lockedExecutable) {
		t.Fatalf("stale receipt replaced newer lock executable: %q", got)
	}
	if got := LoadHookContractLockEntry(dir, "codex"); !validCodexAgentExecutableEvidence(got) {
		t.Fatalf("stale receipt hid authoritative lock: %+v", got)
	}
}

func TestInvalidCodexSetupSelectionsDoNotRepairLegacyLock(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("protected Codex setup selections are native-Windows authority")
	}
	for _, test := range []struct {
		name  string
		write func(*testing.T, string, string, time.Time)
	}{
		{
			name: "expired",
			write: func(t *testing.T, dir, executable string, now time.Time) {
				writeCodexSetupSelectionForTest(
					t, dir, executable, "codex-cli 0.144.3", "0.144.3",
					now.Add(-20*time.Minute), now.Add(-5*time.Minute),
				)
			},
		},
		{
			name: "malformed",
			write: func(t *testing.T, dir, _ string, _ time.Time) {
				if err := atomicWriteFile(filepath.Join(dir, agentSelectionFile), []byte("{"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := testenv.PrivateTempDir(t)
			executable := filepath.Join(dir, "codex.exe")
			if err := atomicWriteFile(executable, []byte("fixture-codex-binary"), 0o700); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC().Truncate(time.Second)
			writeCodexContractLockForTest(t, dir, HookContractLockEntry{
				Connector:              "codex",
				RawAgentVersion:        "codex-cli 0.144.0-alpha.4",
				NormalizedAgentVersion: "0.144.0",
				ContractID:             "codex-hooks-v3",
				CompatibilityStatus:    HookCompatibilityKnown,
			}, now.Add(-time.Minute))
			test.write(t, dir, executable, now)

			if got := LoadCachedAgentVersion(dir, "codex"); got != "" {
				t.Fatalf("invalid receipt repaired legacy version: %q", got)
			}
			if got := LoadCachedAgentExecutable(dir, "codex"); got != "" {
				t.Fatalf("invalid receipt repaired legacy executable: %q", got)
			}
			if got := LoadHookContractLockEntry(dir, "codex"); got.Connector != "codex" {
				t.Fatalf("invalid receipt hid fail-closed legacy lock: %+v", got)
			}
		})
	}
}

func TestExistingCodexLockWithoutExecutableEvidenceFailsClosed(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("protected Codex lock authority is native-Windows-only")
	}
	dir := testenv.PrivateTempDir(t)
	now := time.Now().UTC().Format(time.RFC3339)
	lock := hookContractLock{
		Version:   hookContractLockVersion,
		UpdatedAt: now,
		Connectors: map[string]HookContractLockEntry{
			"codex": {
				Connector:              "codex",
				RawAgentVersion:        "codex 0.144.3",
				NormalizedAgentVersion: "0.144.3",
				ContractID:             "codex-hooks-v3",
				CompatibilityStatus:    HookCompatibilityKnown,
				UpdatedAt:              now,
			},
		},
	}
	body, err := json.Marshal(lock)
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(filepath.Join(dir, hookContractLockFile), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := LoadCachedAgentVersion(dir, "codex"); got != "" {
		t.Fatalf("legacy lock returned version %q", got)
	}
	if got := LoadCachedAgentExecutable(dir, "codex"); got != "" {
		t.Fatalf("legacy lock returned executable %q", got)
	}
}

func TestProtectedCodexLockIsRuntimeExecutableAuthority(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("protected Codex lock authority is native-Windows-only")
	}
	dir := testenv.PrivateTempDir(t)
	executable := filepath.Join(dir, "codex.exe")
	if err := atomicWriteFile(executable, []byte("locked-codex-binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	entry := NewHookContractLockEntry(
		SetupOpts{DataDir: dir, AgentVersion: "codex 0.144.3", AgentExecutable: executable},
		NewCodexConnector(),
		"test-build",
	)
	lock := hookContractLock{
		Version:    hookContractLockVersion,
		UpdatedAt:  time.Now().UTC().Format(time.RFC3339),
		Connectors: map[string]HookContractLockEntry{"codex": entry},
	}
	body, err := json.Marshal(lock)
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(filepath.Join(dir, hookContractLockFile), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := LoadCachedAgentVersion(dir, "codex"); got != "codex 0.144.3" {
		t.Fatalf("locked version = %q", got)
	}
	if got := LoadCachedAgentExecutable(dir, "codex"); !sameCodexExecutablePath(got, executable) {
		t.Fatalf("locked executable = %q, want %q", got, executable)
	}
}
