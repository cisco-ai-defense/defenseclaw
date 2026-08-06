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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func TestCursorContractSeparatesAgentAndDesktopEvidence(t *testing.T) {
	contract := KnownHookContracts("cursor")[0]
	if !stringInSlice(contract.Events, "subagentStart") {
		t.Fatalf("Cursor event roster omitted subagentStart: %v", contract.Events)
	}
	if !contract.Capabilities.CanBlock || contract.Capabilities.CanAskNative || !contract.Capabilities.SupportsFailClosed {
		t.Fatalf("Cursor user-hook action contract is inconsistent: %+v", contract.Capabilities)
	}
	wantBlockEvents := []string{
		"preToolUse", "subagentStart", "beforeShellExecution", "beforeMCPExecution",
		"beforeReadFile", "beforeTabFileRead", "beforeSubmitPrompt",
	}
	if !reflect.DeepEqual(contract.Capabilities.BlockEvents, wantBlockEvents) {
		t.Fatalf("Cursor block events = %v, want %v", contract.Capabilities.BlockEvents, wantBlockEvents)
	}
	joined := strings.Join(contract.Notes, " ")
	for _, want := range []string{
		"cursor_version", "application/Desktop", "Agent CLI", "Enterprise > Team > Project > User",
		"no safe API", "failClosed=true", "does not emit Cursor's native ask",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("Cursor evidence notes missing %q: %s", want, joined)
		}
	}
}

func TestAntigravityDefaultCapabilitiesMatchResolvedContract(t *testing.T) {
	opts := SetupOpts{DataDir: t.TempDir()}
	conn := NewAntigravityConnector()
	direct := conn.HookCapabilities(opts)
	resolved := conn.HookProfile(opts).Capabilities
	if !reflect.DeepEqual(direct, resolved) {
		t.Fatalf("HookCapabilities()=%+v, default resolved contract=%+v", direct, resolved)
	}
}

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
		{"codex_ten_event_selective_minimum", "codex", "codex 0.133.0", HookCompatibilityKnown, "codex-hooks-v3", "0.133.0"},
		{"codex_ten_event_selective_upper_boundary", "codex", "codex 0.134.99", HookCompatibilityKnown, "codex-hooks-v3", "0.134.99"},
		{"codex_generic_function_minimum", "codex", "codex 0.135.0", HookCompatibilityKnown, "codex-hooks-v3-generic", "0.135.0"},
		{"codex_generic_function_upper_boundary", "codex", "codex 0.144.99", HookCompatibilityKnown, "codex-hooks-v3-generic", "0.144.99"},
		{"codex_session_end_minimum", "codex", "codex 0.145.0", HookCompatibilityKnown, "codex-hooks-v4", "0.145.0"},
		{"codex_current", "codex", "codex 0.146.0", HookCompatibilityKnown, "codex-hooks-v4", "0.146.0"},
		{"codex_unversioned_uses_full_default", "codex", "", HookCompatibilityUnversioned, "codex-hooks-v4", ""},
		{"codex_unknown_before_stable", "codex", "codex 0.123.0", HookCompatibilityUnknown, "", "0.123.0"},
		{"claude_before_message_display", "claude-code", "Claude Code v2.1.151", HookCompatibilityUnknown, "", "2.1.151"},
		{"claude_alias_known", "claude-code", "Claude Code v2.1.154", HookCompatibilityKnown, "claudecode-hooks-v1", "2.1.154"},
		{"claude_v1_upper_boundary", "claude-code", "Claude Code v2.1.218", HookCompatibilityKnown, "claudecode-hooks-v1", "2.1.218"},
		{"claude_directory_added_minimum", "claude-code", "Claude Code v2.1.219", HookCompatibilityKnown, "claudecode-hooks-v2", "2.1.219"},
		{"claude_directory_added_current", "claude-code", "Claude Code v2.1.220", HookCompatibilityKnown, "claudecode-hooks-v2", "2.1.220"},
		{"openhands_alias_known", "open-hands", "OpenHands 1.0.0", HookCompatibilityKnown, "openhands-hooks-v1", "1.0.0"},
		{"cursor_exact_agent_preview_pin", "cursor", "2026.07.23-e383d2b", HookCompatibilityKnown, "cursor-hooks-v1", "2026.7.23"},
		{"cursor_exact_agent_preview_command_prefix", "cursor", "agent v2026.07.23-e383d2b", HookCompatibilityKnown, "cursor-hooks-v1", "2026.7.23"},
		{"cursor_other_agent_build_unknown", "cursor", "cursor-agent 2026.07.23-deadbee", HookCompatibilityUnknown, "", "2026.7.23"},
		{"cursor_desktop_version_not_agent_contract", "cursor", "cursor 3.13.21", HookCompatibilityUnknown, "", "3.13.21"},
		{"omnigent_before_proven_floor", "omnigent", "omnigent 0.6.99", HookCompatibilityUnknown, "", "0.6.99"},
		{"omnigent_proven_floor", "omnigent", "omnigent 0.7.0", HookCompatibilityKnown, "omnigent-custom-policy-v1", "0.7.0"},
		{"omnigent_after_reviewed_range", "omnigent", "omnigent 0.8.0", HookCompatibilityUnknown, "", "0.8.0"},
		{"omnigent_unversioned_requires_override", "omnigent", "", HookCompatibilityUnversioned, "omnigent-custom-policy-v1", ""},
		{"opencode_reviewed_pin", "opencode", "opencode 1.18.10", HookCompatibilityKnown, "opencode-hooks-v1", "1.18.10"},
		{"opencode_current_pin", "opencode", "opencode 1.18.11", HookCompatibilityKnown, "opencode-hooks-v1", "1.18.11"},
		{"opencode_next_patch_unknown", "opencode", "opencode 1.18.12", HookCompatibilityUnknown, "", "1.18.12"},
		{"opencode_unversioned_requires_override", "opencode", "", HookCompatibilityUnversioned, "opencode-hooks-v1", ""},
		{"antigravity_before_documented_floor", "antigravity", "Antigravity CLI v1.1.7", HookCompatibilityUnknown, "", "1.1.7"},
		{"antigravity_documented_minimum", "antigravity", "Antigravity CLI v1.1.8", HookCompatibilityKnown, "antigravity-hooks-v2", "1.1.8"},
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

func TestClaudeCodeHookContractDirectoryAddedIsObservationOnly(t *testing.T) {
	tests := []struct {
		version       string
		wantID        string
		wantEvents    int
		wantDirectory bool
	}{
		{"Claude Code 2.1.218", "claudecode-hooks-v1", 28, false},
		{"Claude Code 2.1.219", "claudecode-hooks-v2", 29, true},
		{"Claude Code 2.1.220", "claudecode-hooks-v2", 29, true},
	}
	for _, test := range tests {
		t.Run(test.version, func(t *testing.T) {
			contract := ResolveHookContract("claudecode", test.version).Contract
			if contract.ContractID != test.wantID || len(contract.Events) != test.wantEvents {
				t.Fatalf("contract=%s events=%d, want %s/%d", contract.ContractID, len(contract.Events), test.wantID, test.wantEvents)
			}
			hasDirectory := false
			for _, event := range contract.Events {
				hasDirectory = hasDirectory || event == "DirectoryAdded"
			}
			if hasDirectory != test.wantDirectory {
				t.Fatalf("DirectoryAdded present=%v, want %v", hasDirectory, test.wantDirectory)
			}
			for _, event := range append(append([]string{}, contract.Capabilities.BlockEvents...), contract.Capabilities.AskEvents...) {
				if event == "DirectoryAdded" {
					t.Fatal("DirectoryAdded must not have block or ask authority")
				}
			}
			groups, err := claudeCodeHookGroupsForSetup(SetupOpts{AgentVersion: test.version})
			if err != nil {
				t.Fatalf("version-selected registration groups: %v", err)
			}
			if len(groups) != test.wantEvents {
				t.Fatalf("registration groups=%d, want %d", len(groups), test.wantEvents)
			}
			for _, group := range groups {
				if group.eventType == "DirectoryAdded" && (group.matcher != "" || group.async || group.timeout != 30) {
					t.Fatalf("DirectoryAdded registration=%+v, want matcherless synchronous 30-second hook", group)
				}
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
		{
			version: "0.135.0",
			wantID:  "codex-hooks-v3-generic",
			events: []string{
				"SessionStart", "UserPromptSubmit", "PreToolUse",
				"PermissionRequest", "PostToolUse", "SubagentStart",
				"SubagentStop", "PreCompact", "PostCompact", "Stop",
			},
		},
		{
			version: "0.145.0",
			wantID:  "codex-hooks-v4",
			events: []string{
				"SessionStart", "UserPromptSubmit", "PreToolUse",
				"PermissionRequest", "PostToolUse", "SubagentStart",
				"SubagentStop", "PreCompact", "PostCompact", "Stop",
				"SessionEnd",
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

func TestCodexHookContractPinsLifecycleControlsToV3AndV4(t *testing.T) {
	for _, version := range []string{"0.133.0", "0.135.0", "0.144.0", "0.145.0"} {
		contract := ResolveHookContract("codex", version).Contract
		for _, event := range []string{"SessionStart", "SubagentStop", "PreCompact", "PostCompact"} {
			if !stringInSlice(contract.Capabilities.BlockEvents, event) {
				t.Errorf("%s %s does not own official %s control: %v",
					version, contract.ContractID, event, contract.Capabilities.BlockEvents)
			}
		}
		if stringInSlice(contract.Capabilities.BlockEvents, "SessionEnd") {
			t.Errorf("%s %s incorrectly treats advisory SessionEnd as control", version, contract.ContractID)
		}
		if contract.Capabilities.CanAskNative || len(contract.Capabilities.AskEvents) != 0 {
			t.Errorf("%s %s fabricated native ask: %+v", version, contract.ContractID, contract.Capabilities)
		}
	}
	for _, version := range []string{"0.124.0", "0.129.0"} {
		contract := ResolveHookContract("codex", version).Contract
		for _, event := range []string{"SessionStart", "SubagentStop", "PreCompact", "PostCompact"} {
			if stringInSlice(contract.Capabilities.BlockEvents, event) {
				t.Errorf("%s %s backfilled uncertified %s control", version, contract.ContractID, event)
			}
		}
	}
}

func TestCodexHookContractToolSurfaceBands(t *testing.T) {
	selective := []ToolSurface{
		ToolSurfaceShell, ToolSurfaceFileWrite, ToolSurfaceFileEdit, ToolSurfaceMCP,
	}
	generic := []ToolSurface{
		ToolSurfaceGeneric, ToolSurfaceShell, ToolSurfaceFileWrite, ToolSurfaceFileEdit, ToolSurfaceMCP,
	}
	for _, tc := range []struct {
		version string
		want    []ToolSurface
	}{
		{version: "0.124.0", want: selective},
		{version: "0.129.0", want: selective},
		{version: "0.133.0", want: selective},
		{version: "0.135.0", want: generic},
		{version: "0.145.0", want: generic},
	} {
		t.Run(tc.version, func(t *testing.T) {
			lifecycle := ResolveHookContract("codex", tc.version).Contract.ToolCallLifecycle
			if !reflect.DeepEqual(lifecycle.CoveredToolSurfaces, tc.want) {
				t.Fatalf("covered surfaces = %v, want %v", lifecycle.CoveredToolSurfaces, tc.want)
			}
			if lifecycle.OutcomeAuthority != ToolOutcomeSurfaceSpecific {
				t.Fatalf("outcome authority = %q, want %q", lifecycle.OutcomeAuthority, ToolOutcomeSurfaceSpecific)
			}
			if !reflect.DeepEqual(lifecycle.PreProposalEvents, []string{"PreToolUse"}) {
				t.Fatalf("pre-proposal events = %v, want only PreToolUse", lifecycle.PreProposalEvents)
			}
			if lifecycle.RouteForEvent("PermissionRequest") != ToolEventRouteStructuredAction ||
				lifecycle.IsPreProposalEvent("PermissionRequest") {
				t.Fatal("PermissionRequest must remain a direct structured-action event without proposal authority")
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
	for _, name := range []string{"codex", "claudecode", "hermes", "cursor", "windsurf", "geminicli", "copilot", "openhands", "antigravity", "opencode", "omnigent", "amp"} {
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
			directResponse := name == "omnigent" || name == "amp"
			if contract.ResponseFieldName == "" && !directResponse {
				t.Fatalf("%s contract %s missing response field", name, contract.ContractID)
			}
			if directResponse && contract.ResponseFieldName != "" {
				t.Fatalf("%s contract %s must return its policy verdict directly, not through %q", name, contract.ContractID, contract.ResponseFieldName)
			}
			if err := ValidateToolCallLifecycleContract(contract.ToolCallLifecycle, contract.Events); err != nil {
				t.Fatalf("%s contract %s has invalid tool-call lifecycle: %v", name, contract.ContractID, err)
			}
		}
	}
}

func TestHermesHookContractV019V020ClassifiesAllValidEventsWithoutInventingBlockSurfaces(t *testing.T) {
	if got := ResolveHookContract("hermes", "0.18.99").Status; got != HookCompatibilityUnknown {
		t.Fatalf("Hermes 0.18 compatibility = %q, want unknown for the v0.19 event contract", got)
	}
	resolution := ResolveHookContract("hermes", "0.19.0")
	if resolution.Status != HookCompatibilityKnown {
		t.Fatalf("Hermes 0.19 compatibility = %q, want known", resolution.Status)
	}
	contract := resolution.Contract
	if got := ResolveHookContract("hermes", "Hermes Agent v0.20.0 (2026.8.3)").Status; got != HookCompatibilityKnown {
		t.Fatalf("Hermes 0.20 compatibility = %q, want known", got)
	}
	if got := ResolveHookContract("hermes", "0.21.0").Status; got != HookCompatibilityUnknown {
		t.Fatalf("Hermes 0.21 compatibility = %q, want unknown beyond source-reviewed ceiling", got)
	}
	if len(contract.Events) != 23 {
		t.Fatalf("Hermes event count = %d, want 23: %v", len(contract.Events), contract.Events)
	}
	seen := make(map[string]struct{}, len(contract.Events))
	for _, event := range contract.Events {
		if _, exists := seen[event]; exists {
			t.Fatalf("Hermes event %q appears more than once", event)
		}
		seen[event] = struct{}{}
	}
	for _, event := range []string{
		"pre_tool_call", "pre_llm_call", "pre_verify",
		"transform_terminal_output", "pre_gateway_dispatch",
		"pre_approval_request", "api_request_error", "kanban_task_blocked",
	} {
		if _, ok := seen[event]; !ok {
			t.Errorf("Hermes v0.19 contract missing classified event %q", event)
		}
	}
	if got := contract.Capabilities.BlockEvents; !reflect.DeepEqual(got, []string{"pre_tool_call"}) {
		t.Fatalf("Hermes block events = %v, want only pre_tool_call", got)
	}
	if contract.Capabilities.CanAskNative || contract.Capabilities.SupportsFailClosed {
		t.Fatalf("Hermes contract invented ask/fail-closed support: %+v", contract.Capabilities)
	}
}

func TestOmniGentV070ContractPreservesPostPhaseDenyWithoutPostPhaseAsk(t *testing.T) {
	resolution := ResolveHookContract("omnigent", "omnigent 0.7.0")
	if resolution.Status != HookCompatibilityKnown {
		t.Fatalf("OmniGent v0.7.0 compatibility = %q, want known", resolution.Status)
	}
	contract := resolution.Contract
	if contract.MinAgentVersion != "0.7.0" {
		t.Fatalf("OmniGent minimum version = %q, want 0.7.0", contract.MinAgentVersion)
	}
	if contract.MaxAgentVersion != "0.8.0" {
		t.Fatalf("OmniGent maximum version = %q, want exclusive 0.8.0", contract.MaxAgentVersion)
	}
	if got, want := contract.Events, []string{
		"UserPromptSubmit", "PreToolUse", "PostToolUse",
		"AfterAgentResponse", "BeforeModel", "AfterModel",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("OmniGent events = %v, want %v", got, want)
	}
	wantPre := []string{"UserPromptSubmit", "PreToolUse", "BeforeModel"}
	if !reflect.DeepEqual(contract.Capabilities.AskEvents, wantPre) {
		t.Fatalf("OmniGent ASK events = %v, want %v", contract.Capabilities.AskEvents, wantPre)
	}
	if !reflect.DeepEqual(contract.Capabilities.BlockEvents, contract.Events) {
		t.Fatalf("OmniGent DENY events = %v, want all six %v", contract.Capabilities.BlockEvents, contract.Events)
	}
}

// TestContentEnvelopeKeyDeclarations pins every connector to the official
// top-level payload shape. The generic decoder must never open an undeclared
// sub-object, including an inferred Hermes extra envelope.
func TestContentEnvelopeKeyDeclarations(t *testing.T) {
	for name, contracts := range builtinHookContracts {
		for _, contract := range contracts {
			if contract.ContentEnvelopeKey != "" {
				t.Errorf("%s %s ContentEnvelopeKey=%q want empty", name, contract.ContractID, contract.ContentEnvelopeKey)
			}
		}
	}
	hermes := NewHermesConnector().HookProfile(SetupOpts{APIAddr: "127.0.0.1:18970"})
	if hermes.ContentEnvelopeKey != "" {
		t.Fatalf("hermes profile ContentEnvelopeKey=%q want empty", hermes.ContentEnvelopeKey)
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
			Exact        []string `json:"exact"`
			MinInclusive string   `json:"min_inclusive"`
			MaxExclusive string   `json:"max_exclusive"`
		} `json:"agent_version"`
		DefaultForUnversioned   bool                      `json:"default_for_unversioned"`
		HookScriptVersion       string                    `json:"hook_script_version"`
		HookConfigPathTemplates []string                  `json:"hook_config_path_templates"`
		ResponseField           string                    `json:"response_field"`
		Events                  []string                  `json:"events"`
		AIDSurfaces             []string                  `json:"aid_surfaces"`
		SupportsTraceparent     bool                      `json:"supports_traceparent"`
		NativeOTLP              bool                      `json:"native_otlp"`
		ContentEnvelopeKey      string                    `json:"content_envelope_key"`
		ToolCallLifecycle       ToolCallLifecycleContract `json:"tool_call_lifecycle"`
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
			if !sameStrings(manifestContract.AgentVersion.Exact, runtime.ExactAgentVersions) {
				t.Fatalf("%s exact versions=%v want %v", runtime.ContractID, manifestContract.AgentVersion.Exact, runtime.ExactAgentVersions)
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
			if !reflect.DeepEqual(manifestContract.ToolCallLifecycle, runtime.ToolCallLifecycle) {
				t.Fatalf("%s tool_call_lifecycle manifest/runtime drift:\nmanifest=%+v\nruntime=%+v", runtime.ContractID, manifestContract.ToolCallLifecycle, runtime.ToolCallLifecycle)
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
		AgentVersion: "Claude Code v2.1.154",
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
	if profile.ToolCallLifecycle.Version != ToolCallLifecycleContractVersion || !profile.ToolCallLifecycle.SupportsExactInvocationJoin() {
		t.Fatalf("Claude Code lifecycle contract was not resolved: %+v", profile.ToolCallLifecycle)
	}
	profile.ToolCallLifecycle.PreProposalEvents[0] = "mutated"
	resolved := ResolveHookContract("claudecode", "2.1.154")
	if resolved.Contract.ToolCallLifecycle.PreProposalEvents[0] != "PreToolUse" {
		t.Fatal("resolved HookProfile aliases the built-in lifecycle contract")
	}
}

func TestToolCallLifecycleRuntimeHelpers(t *testing.T) {
	claude := ResolveHookContract("claudecode", "2.1.154").Contract.ToolCallLifecycle
	if got := claude.RouteForEvent("PreToolUse"); got != ToolEventRouteStructuredAction {
		t.Fatalf("Claude PreToolUse route=%q", got)
	}
	if got := claude.RouteForEvent("PostToolUseFailure"); got != ToolEventRouteResultContent {
		t.Fatalf("Claude PostToolUseFailure route=%q", got)
	}
	if got := claude.RouteForEvent("ConfigChange"); got != ToolEventRouteUnknown {
		t.Fatalf("Claude ConfigChange route=%q want unknown", got)
	}
	if got := claude.RouteForEvent("UserPromptSubmit"); got != ToolEventRouteUnknown {
		t.Fatalf("Claude prompt route=%q want unknown", got)
	}
	if claude.IsStateTransitionEvent("ConfigChange") || claude.IsPreProposalEvent("ConfigChange") {
		t.Fatal("Claude ConfigChange must not claim tool or typed-state authority")
	}
	if claude.IsAuthoritativeTerminalEvent("SubagentStop") {
		t.Fatal("session-scoped pending state treated child stop as session terminal")
	}
	if !claude.IsPreProposalEvent("PreToolUse") || !claude.ExactInvocationJoinEligible("PostToolUse") {
		t.Fatal("Claude exact proposal/result lifecycle is not join eligible")
	}
	if claude.IsPreProposalEvent("PermissionRequest") ||
		claude.RouteForEvent("PermissionRequest") != ToolEventRouteStructuredAction {
		t.Fatal("Claude PermissionRequest must remain direct-only without proposal authority")
	}
	if got := claude.ClassifyTerminalOutcome("claudecode", "PermissionDenied", nil); got != ToolLifecycleOutcomeDenied {
		t.Fatalf("Claude denial outcome=%q", got)
	}
	copilot := ResolveHookContract("copilot", "1.0.18").Contract.ToolCallLifecycle
	if copilot.IsAuthoritativeTerminalEvent("subagentStop") {
		t.Fatal("Copilot subagent stop must not clear session-wide pending state")
	}

	cases := []struct {
		name      string
		connector string
		version   string
		event     string
		payload   map[string]interface{}
		want      ToolLifecycleOutcome
	}{
		{
			name:      "hermes_success_status",
			connector: "hermes", event: "post_tool_call",
			payload: map[string]interface{}{"extra": map[string]interface{}{"status": "ok"}},
			want:    ToolLifecycleOutcomeSuccess,
		},
		{
			name:      "hermes_blocked_status",
			connector: "hermes", event: "post_tool_call",
			payload: map[string]interface{}{"extra": map[string]interface{}{"status": "blocked"}},
			want:    ToolLifecycleOutcomeDenied,
		},
		{
			name:      "gemini_error",
			connector: "geminicli", event: "AfterTool",
			payload: map[string]interface{}{"tool_response": map[string]interface{}{"error": "command failed"}},
			want:    ToolLifecycleOutcomeFailure,
		},
		{
			name:      "gemini_missing_response_is_unknown",
			connector: "geminicli", event: "AfterTool",
			payload: map[string]interface{}{},
			want:    ToolLifecycleOutcomeUnknown,
		},
		{
			name:      "openhands_explicit_success",
			connector: "openhands", event: "post_tool_use",
			payload: map[string]interface{}{"tool_response": map[string]interface{}{"is_error": false}},
			want:    ToolLifecycleOutcomeSuccess,
		},
		{
			name:      "antigravity_requires_step",
			connector: "antigravity", event: "PostToolUse",
			payload: map[string]interface{}{},
			want:    ToolLifecycleOutcomeUnknown,
		},
		{
			name:      "codex_shell_scalar_response_is_unknown",
			connector: "codex", version: "0.135.0", event: "PostToolUse",
			payload: map[string]interface{}{
				"tool_name":     "shell",
				"tool_input":    map[string]interface{}{"command": "exit 7"},
				"tool_response": "Chunk ID: 5d7f2a\nProcess exited with code 7\nFinal output:\n",
			},
			want: ToolLifecycleOutcomeUnknown,
		},
		{
			name:      "codex_generic_status_object_is_unknown",
			connector: "codex", version: "0.135.0", event: "PostToolUse",
			payload: map[string]interface{}{
				"tool_name":     "custom_function",
				"tool_input":    map[string]interface{}{"value": "test"},
				"tool_response": map[string]interface{}{"status": "completed", "success": true},
			},
			want: ToolLifecycleOutcomeUnknown,
		},
		{
			name:      "codex_apply_patch_scalar_response_is_success",
			connector: "codex", version: "0.135.0", event: "PostToolUse",
			payload: map[string]interface{}{
				"tool_name": "apply_patch",
				"tool_input": map[string]interface{}{
					"command": "*** Begin Patch\n*** Add File: hello.txt\n+hello\n*** End Patch",
				},
				"tool_response": "Success. Updated files.",
			},
			want: ToolLifecycleOutcomeSuccess,
		},
		{
			name:      "codex_mcp_call_tool_result_without_error_is_success",
			connector: "codex", version: "0.135.0", event: "PostToolUse",
			payload: map[string]interface{}{
				"tool_name":  "mcp__github__get_issue",
				"tool_input": map[string]interface{}{"owner": "example", "repo": "project", "issue_number": float64(1)},
				"tool_response": map[string]interface{}{
					"content": []interface{}{map[string]interface{}{"type": "text", "text": "issue"}},
				},
			},
			want: ToolLifecycleOutcomeSuccess,
		},
		{
			name:      "codex_mcp_call_tool_result_error_is_failure",
			connector: "codex", version: "0.135.0", event: "PostToolUse",
			payload: map[string]interface{}{
				"tool_name":  "mcp__github__get_issue",
				"tool_input": map[string]interface{}{"owner": "example", "repo": "project", "issue_number": float64(1)},
				"tool_response": map[string]interface{}{
					"content": []interface{}{map[string]interface{}{"type": "text", "text": "not found"}},
					"isError": true,
				},
			},
			want: ToolLifecycleOutcomeFailure,
		},
		{
			name:      "codex_mcp_call_tool_result_false_error_is_success",
			connector: "codex", version: "0.135.0", event: "PostToolUse",
			payload: map[string]interface{}{
				"tool_name":  "mcp__github__get_issue",
				"tool_input": map[string]interface{}{},
				"tool_response": map[string]interface{}{
					"content": []interface{}{},
					"isError": false,
				},
			},
			want: ToolLifecycleOutcomeSuccess,
		},
		{
			name:      "codex_mcp_response_without_input_is_unknown",
			connector: "codex", version: "0.135.0", event: "PostToolUse",
			payload: map[string]interface{}{
				"tool_name": "mcp__github__get_issue",
				"tool_response": map[string]interface{}{
					"content": []interface{}{},
				},
			},
			want: ToolLifecycleOutcomeUnknown,
		},
		{
			name:      "codex_mcp_response_without_content_is_unknown",
			connector: "codex", version: "0.135.0", event: "PostToolUse",
			payload: map[string]interface{}{
				"tool_name":     "mcp__github__get_issue",
				"tool_input":    map[string]interface{}{"owner": "example", "repo": "project", "issue_number": float64(1)},
				"tool_response": map[string]interface{}{"isError": false},
			},
			want: ToolLifecycleOutcomeUnknown,
		},
		{
			name:      "opencode_missing_result",
			connector: "opencode", event: "tool.execute.after",
			payload: map[string]interface{}{},
			want:    ToolLifecycleOutcomeUnknown,
		},
		{
			name:      "opencode_empty_result_object",
			connector: "opencode", event: "tool.execute.after",
			payload: map[string]interface{}{"tool_response": map[string]interface{}{}},
			want:    ToolLifecycleOutcomeUnknown,
		},
		{
			name:      "opencode_result_requires_string_output",
			connector: "opencode", event: "tool.execute.after",
			payload: map[string]interface{}{
				"tool_response": map[string]interface{}{"output": map[string]interface{}{}},
			},
			want: ToolLifecycleOutcomeUnknown,
		},
		{
			name:      "opencode_empty_string_result_is_success",
			connector: "opencode", event: "tool.execute.after",
			payload: map[string]interface{}{
				"tool_response": map[string]interface{}{"output": ""},
			},
			want: ToolLifecycleOutcomeSuccess,
		},
		{
			name:      "opencode_bash_zero_exit_is_success",
			connector: "opencode", event: "tool.execute.after",
			payload: map[string]interface{}{
				"tool_name": "bash",
				"tool_response": map[string]interface{}{
					"output": "", "metadata": map[string]interface{}{"exit": float64(0)},
				},
			},
			want: ToolLifecycleOutcomeSuccess,
		},
		{
			name:      "opencode_bash_nonzero_exit_is_failure",
			connector: "opencode", event: "tool.execute.after",
			payload: map[string]interface{}{
				"tool_name": "bash",
				"tool_response": map[string]interface{}{
					"output": "failed", "metadata": map[string]interface{}{"exit": float64(7)},
				},
			},
			want: ToolLifecycleOutcomeFailure,
		},
		{
			name:      "opencode_bash_null_exit_is_unknown",
			connector: "opencode", event: "tool.execute.after",
			payload: map[string]interface{}{
				"tool_name": "bash",
				"tool_response": map[string]interface{}{
					"output": "timeout", "metadata": map[string]interface{}{"exit": nil},
				},
			},
			want: ToolLifecycleOutcomeUnknown,
		},
		{
			name:      "opencode_bash_missing_exit_is_unknown",
			connector: "opencode", event: "tool.execute.after",
			payload: map[string]interface{}{
				"tool_name": "bash",
				"tool_response": map[string]interface{}{
					"output": "", "metadata": map[string]interface{}{},
				},
			},
			want: ToolLifecycleOutcomeUnknown,
		},
		{
			name:      "amp_done_is_success",
			connector: "amp", event: "tool.result",
			payload: map[string]interface{}{
				"status": "done",
			},
			want: ToolLifecycleOutcomeSuccess,
		},
		{
			name:      "amp_error_is_failure",
			connector: "amp", event: "tool.result",
			payload: map[string]interface{}{
				"status": "error", "error": "command failed",
			},
			want: ToolLifecycleOutcomeFailure,
		},
		{
			name:      "amp_cancelled_is_cancelled",
			connector: "amp", event: "tool.result",
			payload: map[string]interface{}{
				"status": "cancelled",
			},
			want: ToolLifecycleOutcomeCancelled,
		},
		{
			name:      "amp_done_with_error_is_unknown",
			connector: "amp", event: "tool.result",
			payload: map[string]interface{}{
				"status": "done", "error": "contradictory",
			},
			want: ToolLifecycleOutcomeUnknown,
		},
		{
			name:      "amp_missing_status_is_unknown",
			connector: "amp", event: "tool.result",
			payload: map[string]interface{}{},
			want:    ToolLifecycleOutcomeUnknown,
		},
		{
			name:      "amp_uppercase_status_is_unknown",
			connector: "amp", event: "tool.result",
			payload: map[string]interface{}{"status": "DONE"},
			want:    ToolLifecycleOutcomeUnknown,
		},
		{
			name:      "amp_padded_status_is_unknown",
			connector: "amp", event: "tool.result",
			payload: map[string]interface{}{"status": " done "},
			want:    ToolLifecycleOutcomeUnknown,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			contract := ResolveHookContract(tc.connector, tc.version).Contract.ToolCallLifecycle
			if got := contract.ClassifyTerminalOutcome(tc.connector, tc.event, tc.payload); got != tc.want {
				t.Fatalf("outcome=%q want %q", got, tc.want)
			}
		})
	}

	for _, connectorName := range []string{"windsurf", "geminicli", "copilot", "openhands", "omnigent"} {
		contract := ResolveHookContract(connectorName, "").Contract.ToolCallLifecycle
		if contract.SupportsExactInvocationJoin() {
			t.Fatalf("%s must not claim exact invocation joins", connectorName)
		}
	}
	antigravity := ResolveHookContract("antigravity", "1.1.9").Contract
	antigravity.ToolCallLifecycle.StatefulEnforcementLevel = StatefulToolPairedOutcomes
	if err := ValidateToolCallLifecycleContract(antigravity.ToolCallLifecycle, antigravity.Events); err == nil {
		t.Fatal("paired sequence must not be promoted to exact paired-outcome enforcement")
	}
	amp := ResolveHookContract("amp", "0.0.1785334225").Contract.ToolCallLifecycle
	if !amp.SupportsExactInvocationJoin() || !amp.IsPreProposalEvent("tool.call") ||
		!amp.ExactInvocationJoinEligible("tool.result") ||
		!amp.IsAuthoritativePendingDiscardEvent("agent.end") {
		t.Fatal("Amp exact proposal/result lifecycle is incomplete")
	}
}

func TestToolCallLifecycleTerminalResetEventsAreSessionScoped(t *testing.T) {
	for _, tc := range []struct {
		connector      string
		version        string
		event          string
		terminal       bool
		discardPending bool
	}{
		{connector: "codex", version: "0.146.0", event: "Stop", discardPending: true},
		{connector: "codex", version: "0.146.0", event: "SessionEnd", terminal: true},
		{connector: "claudecode", version: "2.1.154", event: "Stop", discardPending: true},
		{connector: "claudecode", version: "2.1.154", event: "StopFailure", discardPending: true},
		{connector: "claudecode", version: "2.1.154", event: "SessionEnd", terminal: true},
		{connector: "hermes", event: "subagent_stop"},
		{connector: "hermes", event: "on_session_end", terminal: true},
		{connector: "hermes", event: "on_session_finalize", terminal: true},
		{connector: "hermes", event: "on_session_reset", terminal: true},
		{connector: "cursor", event: "stop", discardPending: true},
		{connector: "cursor", event: "sessionEnd", terminal: true},
		{connector: "windsurf", event: "post_cascade_response", discardPending: true},
		{connector: "windsurf", event: "post_cascade_response_with_transcript", discardPending: true},
		{connector: "geminicli", event: "AfterAgent", discardPending: true},
		{connector: "geminicli", event: "SessionEnd", terminal: true},
		{connector: "copilot", event: "agentStop", discardPending: true},
		{connector: "copilot", event: "sessionEnd", terminal: true},
		{connector: "openhands", event: "stop", discardPending: true},
		{connector: "openhands", event: "session_end", terminal: true},
		{connector: "antigravity", version: "1.1.9", event: "Stop", discardPending: true},
		{connector: "opencode", event: "session.idle", discardPending: true},
		{connector: "opencode", event: "session.deleted", terminal: true},
		{connector: "amp", event: "session.start"},
		{connector: "amp", event: "agent.end", discardPending: true},
		{connector: "omnigent", event: "AfterAgentResponse", discardPending: true},
	} {
		t.Run(tc.connector+"/"+tc.event, func(t *testing.T) {
			contract := ResolveHookContract(tc.connector, tc.version).Contract
			if !containsExact(contract.Events, tc.event) {
				t.Fatalf("reviewed event %q is not declared by %s", tc.event, contract.ContractID)
			}
			if got := contract.ToolCallLifecycle.IsAuthoritativeTerminalEvent(tc.event); got != tc.terminal {
				t.Fatalf("terminal=%t want %t", got, tc.terminal)
			}
			if got := contract.ToolCallLifecycle.IsAuthoritativePendingDiscardEvent(tc.event); got != tc.discardPending {
				t.Fatalf("pending discard=%t want %t", got, tc.discardPending)
			}
		})
	}

	for _, version := range []string{"0.124.0", "0.129.0", "0.133.0", "0.135.0", "0.144.0"} {
		contract := ResolveHookContract("codex", version).Contract
		if got := contract.ToolCallLifecycle.AuthoritativeTerminalEvents; len(got) != 0 {
			t.Fatalf("Codex %s terminal reset events=%v before SessionEnd support", version, got)
		}
	}
}

func TestToolCallLifecycleStateTransitionRouteIsReservedAndEmpty(t *testing.T) {
	for connectorName, contracts := range builtinHookContracts {
		for _, contract := range contracts {
			transitions := contract.ToolCallLifecycle.Routing.StateTransitionEvents
			if len(transitions) != 0 {
				t.Fatalf("unsupported state-transition route for %s/%s: %v", connectorName, contract.ContractID, transitions)
			}
		}
	}

	synthetic := ResolveHookContract("claudecode", "2.1.154").Contract
	synthetic.ToolCallLifecycle.Routing.StateTransitionEvents = []string{"ConfigChange"}
	if got := synthetic.ToolCallLifecycle.RouteForEvent("ConfigChange"); got != ToolEventRouteStateTransition {
		t.Fatalf("reserved state-transition route=%q", got)
	}
	if !synthetic.ToolCallLifecycle.IsStateTransitionEvent("ConfigChange") || synthetic.ToolCallLifecycle.IsPreProposalEvent("ConfigChange") {
		t.Fatal("reserved state transition was treated as a tool proposal")
	}
	if err := ValidateToolCallLifecycleContract(synthetic.ToolCallLifecycle, synthetic.Events); err != nil {
		t.Fatalf("valid reserved state-transition route rejected: %v", err)
	}

	cloned := cloneToolCallLifecycleContract(synthetic.ToolCallLifecycle)
	cloned.Routing.StateTransitionEvents[0] = "mutated"
	if synthetic.ToolCallLifecycle.Routing.StateTransitionEvents[0] != "ConfigChange" {
		t.Fatal("state-transition route aliases its clone")
	}

	synthetic.ToolCallLifecycle.Routing.StructuredActionEvents = append(
		synthetic.ToolCallLifecycle.Routing.StructuredActionEvents,
		"ConfigChange",
	)
	if err := ValidateToolCallLifecycleContract(synthetic.ToolCallLifecycle, synthetic.Events); err == nil {
		t.Fatal("state-transition event shared with a tool route must be rejected")
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
	if profile.ExperimentalToolLifecycleEligible() {
		t.Fatal("known version mismatch retained experimental lifecycle authority")
	}
	unversioned := NewCodexConnector().HookProfile(SetupOpts{
		APIAddr: "127.0.0.1:18970",
	})
	if !unversioned.ExperimentalToolLifecycleEligible() {
		t.Fatal("reviewed unversioned default lost experimental lifecycle authority")
	}
}

func TestHookContractLockSaveLoadAndDrift(t *testing.T) {
	dir := testenv.PrivateTempDir(t)
	conn := NewHermesConnector()
	opts := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:18970"}
	opts = prepareHermesSetupAdmissionFixture(t, opts)
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

func TestWindowsHermesLockSealsManagedExecutableVersionEvidence(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("protected Hermes executable evidence is native-Windows-only")
	}
	dir := testenv.PrivateTempDir(t)
	opts := prepareHermesSetupAdmissionFixture(t, SetupOpts{DataDir: dir})
	executable := opts.AgentExecutable
	entry := NewHookContractLockEntry(opts, NewHermesConnector(), "test-build")
	if !validSetupSelectedAgentExecutableEvidence(entry, "hermes") ||
		entry.AgentExecutableSource != "setup-selected" ||
		entry.NormalizedAgentVersion != "0.20.0" {
		t.Fatalf("Hermes protected lock evidence = %+v", entry)
	}
	if err := SaveFreshHookContractLockEntry(dir, entry); err != nil {
		t.Fatal(err)
	}
	if got := LoadCachedAgentVersion(dir, "hermes"); got != opts.AgentVersion {
		t.Fatalf("locked Hermes version = %q, want %q", got, opts.AgentVersion)
	}
	if got := LoadCachedAgentExecutable(dir, "hermes"); !strings.EqualFold(got, executable) {
		t.Fatalf("locked Hermes executable = %q, want %q", got, executable)
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
			"amp":        {Connector: "amp", HookScriptDigests: map[string]string{"defenseclaw.ts": "sha256:amp-plugin"}},
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
	amp := LoadHookContractLockEntry(dir, "amp")
	if got := amp.HookScriptDigests[windowsHookBinaryName]; got != "" {
		t.Fatalf("amp inherited unrelated launcher digest %q", got)
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

	t.Run("Amp relative release age is presentation-only", func(t *testing.T) {
		previous := HookContractLockEntry{
			Connector:              "amp",
			RawAgentVersion:        "0.0.1785342457-g1011d5 (released 2026-07-29T16:27:37.000Z, 2h ago)",
			NormalizedAgentVersion: "0.0.1785342457",
			ContractID:             "amp-plugin-v1",
		}
		current := previous
		current.RawAgentVersion = "0.0.1785342457-g1011d5 (released 2026-07-29T16:27:37.000Z, 3h ago)"
		if HookContractCompatibilityDrifted(previous, current) {
			t.Fatal("Amp's changing relative release-age annotation must not cause contract drift")
		}

		current.RawAgentVersion = "0.0.1785342457-gdifferent (released 2026-07-29T16:27:37.000Z, 3h ago)"
		if !HookContractCompatibilityDrifted(previous, current) {
			t.Fatal("Amp's stable version+commit identity change must remain contract drift")
		}
	})

	t.Run("other raw prerelease identities remain significant", func(t *testing.T) {
		previous := HookContractLockEntry{
			Connector:              "codex",
			RawAgentVersion:        "codex-cli 0.144.0-alpha.4",
			NormalizedAgentVersion: "0.144.0",
			ContractID:             "codex-hooks-v1",
		}
		current := previous
		current.RawAgentVersion = "codex-cli 0.144.0-alpha.5"
		if !HookContractCompatibilityDrifted(previous, current) {
			t.Fatal("non-Amp raw prerelease identity changes must remain contract drift")
		}
	})
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

func TestSetupSelectionReceiptCarriesProtectedAgentsForGatewayConsumption(t *testing.T) {
	dir := testenv.PrivateTempDir(t)
	now := time.Now().UTC().Truncate(time.Second)
	receipt := agentSelectionReceipt{
		SchemaVersion: agentSelectionSchemaVersion,
		UpdatedAt:     now.Format(time.RFC3339),
		Selections: map[string]agentSelectionEvidence{
			"codex": {
				Connector:         "codex",
				Source:            "setup-selected",
				Executable:        filepath.Join(dir, "codex.exe"),
				RawVersion:        "codex 0.144.3",
				NormalizedVersion: "0.144.3",
				SHA256:            strings.Repeat("a", 64),
				SelectedAt:        now.Format(time.RFC3339),
				ExpiresAt:         now.Add(agentSelectionMaxLifetime).Format(time.RFC3339),
			},
			"hermes": {
				Connector:         "hermes",
				Source:            "setup-selected",
				Executable:        filepath.Join(dir, "hermes.exe"),
				RawVersion:        "Hermes Agent v0.20.0",
				NormalizedVersion: "0.20.0",
				SHA256:            strings.Repeat("b", 64),
				SelectedAt:        now.Format(time.RFC3339),
				ExpiresAt:         now.Add(agentSelectionMaxLifetime).Format(time.RFC3339),
			},
			"opencode": {
				Connector:         "opencode",
				Source:            "setup-selected",
				Executable:        filepath.Join(dir, "opencode.exe"),
				RawVersion:        "opencode 1.18.11",
				NormalizedVersion: "1.18.11",
				SHA256:            strings.Repeat("c", 64),
				SelectedAt:        now.Format(time.RFC3339),
				ExpiresAt:         now.Add(agentSelectionMaxLifetime).Format(time.RFC3339),
			},
			"amp": {
				Connector:         "amp",
				Source:            "setup-selected",
				Executable:        filepath.Join(dir, "amp.exe"),
				RawVersion:        "0.0.1785875347-gbc402f",
				NormalizedVersion: "0.0.1785875347",
				SHA256:            strings.Repeat("d", 64),
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

	codexSelection, ok := loadSetupAgentSelection(dir, "codex")
	if !ok || codexSelection.Executable != filepath.Join(dir, "codex.exe") {
		t.Fatalf("Codex selection = %+v, %t", codexSelection, ok)
	}
	hermesSelection, ok := loadSetupAgentSelection(dir, "hermes")
	if !ok || hermesSelection.Executable != filepath.Join(dir, "hermes.exe") {
		t.Fatalf("Hermes selection = %+v, %t", hermesSelection, ok)
	}
	opencodeSelection, ok := loadSetupAgentSelection(dir, "opencode")
	if !ok || opencodeSelection.Executable != filepath.Join(dir, "opencode.exe") {
		t.Fatalf("OpenCode selection = %+v, %t", opencodeSelection, ok)
	}
	if got := LoadCachedAgentVersion(dir, "opencode"); got != "opencode 1.18.11" {
		t.Fatalf("OpenCode selected version = %q", got)
	}
	if got := LoadCachedAgentExecutable(dir, "opencode"); got != filepath.Join(dir, "opencode.exe") {
		t.Fatalf("OpenCode selected executable = %q", got)
	}
	ampSelection, ok := loadSetupAgentSelection(dir, "amp")
	if !ok || ampSelection.Executable != filepath.Join(dir, "amp.exe") {
		t.Fatalf("Amp selection = %+v, %t", ampSelection, ok)
	}
	if got := LoadCachedAgentVersion(dir, "amp"); got != "0.0.1785875347-gbc402f" {
		t.Fatalf("Amp selected version = %q", got)
	}
	if got := LoadCachedAgentExecutable(dir, "amp"); got != filepath.Join(dir, "amp.exe") {
		t.Fatalf("Amp selected executable = %q", got)
	}
}

func writeAmpSetupSelectionForTest(
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
		t.Fatal("could not hash fixture Amp executable")
	}
	selection := agentSelectionEvidence{
		Connector:         "amp",
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
		Selections:    map[string]agentSelectionEvidence{"amp": selection},
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

func writeAmpContractLockForTest(t *testing.T, dir string, entry HookContractLockEntry, updatedAt time.Time) {
	t.Helper()
	entry.UpdatedAt = updatedAt.Format(time.RFC3339)
	lock := hookContractLock{
		Version:    hookContractLockVersion,
		UpdatedAt:  updatedAt.Format(time.RFC3339),
		Connectors: map[string]HookContractLockEntry{"amp": entry},
	}
	body, err := json.Marshal(lock)
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(filepath.Join(dir, hookContractLockFile), body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAmpSetupSelectionRejectsUnsupportedOrForeignEvidence(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("protected Amp setup selections are native-Windows authority")
	}
	for _, test := range []struct {
		name       string
		raw        string
		normalized string
	}{
		{name: "fake", raw: "not-an-amp-version", normalized: "0.0.1785875347"},
		{name: "unsupported", raw: "amp 0.0.1", normalized: "0.0.1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := testenv.PrivateTempDir(t)
			executable := filepath.Join(dir, "amp.exe")
			if err := atomicWriteFile(executable, []byte("fixture Amp"), 0o700); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC().Truncate(time.Second)
			writeAmpSetupSelectionForTest(
				t, dir, executable, test.raw, test.normalized, now, now.Add(agentSelectionMaxLifetime),
			)
			if resolution := ResolveHookContract("amp", test.raw); resolution.Status == HookCompatibilityKnown {
				t.Fatalf("test version unexpectedly resolved known: %+v", resolution)
			}
			if selection, ok := loadSetupAgentSelection(dir, "amp"); ok {
				t.Fatalf("unsupported Amp evidence loaded: %+v", selection)
			}
		})
	}
}

func TestAmpExpiredOrOlderMatchingReceiptCannotSupersedeSealedLock(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("protected Amp setup selections are native-Windows authority")
	}
	for _, test := range []struct {
		name       string
		selectedAt func(time.Time) time.Time
		expiresAt  func(time.Time) time.Time
	}{
		{
			name:       "expired",
			selectedAt: func(now time.Time) time.Time { return now.Add(-20 * time.Minute) },
			expiresAt:  func(now time.Time) time.Time { return now.Add(-5 * time.Minute) },
		},
		{
			name:       "older-matching",
			selectedAt: func(now time.Time) time.Time { return now.Add(-2 * time.Minute) },
			expiresAt:  func(now time.Time) time.Time { return now.Add(5 * time.Minute) },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := testenv.PrivateTempDir(t)
			executable := filepath.Join(dir, "amp.exe")
			if err := atomicWriteFile(executable, []byte("sealed Amp"), 0o700); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC().Truncate(time.Second)
			locked := NewHookContractLockEntry(
				SetupOpts{DataDir: dir, AgentVersion: "0.0.1785875347-gbc402f", AgentExecutable: executable},
				NewAMPConnector(),
				"test-build",
			)
			if !validSetupSelectedAgentExecutableEvidence(locked, "amp") {
				t.Fatalf("Amp lock lacks sealed executable evidence: %+v", locked)
			}
			writeAmpContractLockForTest(t, dir, locked, now.Add(-time.Minute))
			writeAmpSetupSelectionForTest(
				t,
				dir,
				executable,
				locked.RawAgentVersion,
				locked.NormalizedAgentVersion,
				test.selectedAt(now),
				test.expiresAt(now),
			)

			if selection, supersedes := supersedingProtectedSetupSelection(dir, "amp", locked); supersedes {
				t.Fatalf("%s Amp receipt superseded sealed lock: %+v", test.name, selection)
			}
			if got := LoadHookContractLockEntry(dir, "amp"); !validSetupSelectedAgentExecutableEvidence(got, "amp") {
				t.Fatalf("%s Amp receipt hid sealed lock: %+v", test.name, got)
			}
		})
	}
}

func TestNewerDifferentAmpReceiptSupersedesThenFreshSealRegainsAuthority(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("protected Amp setup selections are native-Windows authority")
	}
	dir := testenv.PrivateTempDir(t)
	now := time.Now().UTC().Truncate(time.Second)
	oldExecutable := filepath.Join(dir, "old", "amp.exe")
	if err := os.MkdirAll(filepath.Dir(oldExecutable), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(oldExecutable, []byte("old Amp"), 0o700); err != nil {
		t.Fatal(err)
	}
	oldEntry := NewHookContractLockEntry(
		SetupOpts{DataDir: dir, AgentVersion: "0.0.1785875347-gbc402f", AgentExecutable: oldExecutable},
		NewAMPConnector(),
		"old-build",
	)
	writeAmpContractLockForTest(t, dir, oldEntry, now.Add(-2*time.Minute))

	newExecutable := filepath.Join(dir, "current", "amp.exe")
	if err := os.MkdirAll(filepath.Dir(newExecutable), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(newExecutable, []byte("current Amp"), 0o700); err != nil {
		t.Fatal(err)
	}
	selection := writeAmpSetupSelectionForTest(
		t,
		dir,
		newExecutable,
		"0.0.1785875347-gbc402f",
		"0.0.1785875347",
		now,
		now.Add(agentSelectionMaxLifetime),
	)
	if previous := LoadHookContractLockEntry(dir, "amp"); previous.Connector != "" {
		t.Fatalf("newer different Amp receipt did not supersede old lock: %+v", previous)
	}
	if got := LoadCachedAgentExecutable(dir, "amp"); !strings.EqualFold(got, newExecutable) {
		t.Fatalf("Amp repair executable = %q, want %q", got, newExecutable)
	}

	newEntry := NewHookContractLockEntry(
		SetupOpts{DataDir: dir, AgentVersion: selection.RawVersion, AgentExecutable: newExecutable},
		NewAMPConnector(),
		"new-build",
	)
	if err := SaveFreshHookContractLockEntry(dir, newEntry); err != nil {
		t.Fatalf("persist repaired Amp lock: %v", err)
	}
	sealed := LoadHookContractLockEntry(dir, "amp")
	if !validSetupSelectedAgentExecutableEvidence(sealed, "amp") ||
		!protectedSelectionMatchesLock(selection, sealed) {
		t.Fatalf("fresh Amp seal did not regain authority: %+v", sealed)
	}
	if receipt, supersedes := supersedingProtectedSetupSelection(dir, "amp", sealed); supersedes {
		t.Fatalf("matching receipt displaced fresh Amp seal: %+v", receipt)
	}
}

func TestAmpAuthorityNeverFallsBackToAnotherConnectorCacheOrReceipt(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("protected Amp setup selections are native-Windows authority")
	}
	dir := testenv.PrivateTempDir(t)
	now := time.Now().UTC().Truncate(time.Second)
	foreignExecutable := filepath.Join(dir, "opencode.exe")
	if err := atomicWriteFile(foreignExecutable, []byte("foreign connector"), 0o700); err != nil {
		t.Fatal(err)
	}
	_, digest, ok := setupSelectedAgentExecutableEvidence(foreignExecutable)
	if !ok {
		t.Fatal("could not hash foreign connector fixture")
	}
	receipt := agentSelectionReceipt{
		SchemaVersion: agentSelectionSchemaVersion,
		UpdatedAt:     now.Format(time.RFC3339),
		Selections: map[string]agentSelectionEvidence{
			"opencode": {
				Connector: "opencode", Source: "setup-selected", Executable: foreignExecutable,
				RawVersion: "opencode 1.18.11", NormalizedVersion: "1.18.11", SHA256: digest,
				SelectedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(agentSelectionMaxLifetime).Format(time.RFC3339),
			},
		},
	}
	receiptBody, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(filepath.Join(dir, agentSelectionFile), receiptBody, 0o600); err != nil {
		t.Fatal(err)
	}
	cacheBody := []byte(`{"agents":{"copilot":{"version":"1.0.78","binary_path":"C:\\stale\\copilot.exe"}}}`)
	if err := atomicWriteFile(filepath.Join(dir, "agent_discovery.json"), cacheBody, 0o600); err != nil {
		t.Fatal(err)
	}

	if got := LoadCachedAgentVersion(dir, "amp"); got != "" {
		t.Fatalf("Amp consumed foreign cached version %q", got)
	}
	if got := LoadCachedAgentExecutable(dir, "amp"); got != "" {
		t.Fatalf("Amp consumed foreign cached executable %q", got)
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
		ContractID:             "codex-hooks-v3-generic",
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
				ContractID:             "codex-hooks-v3-generic",
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
				ContractID:             "codex-hooks-v3-generic",
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
