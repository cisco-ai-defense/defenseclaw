// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

type nativeSkillHookResponse struct {
	Action           string                 `json:"action"`
	RawAction        string                 `json:"raw_action"`
	Reason           string                 `json:"reason"`
	CodexOutput      map[string]interface{} `json:"codex_output"`
	ClaudeCodeOutput map[string]interface{} `json:"claude_code_output"`
}

type nativeSkillRuntimeAuditCapture struct {
	records []observability.Record
}

func (capture *nativeSkillRuntimeAuditCapture) EmitRuntimeV8(
	_ context.Context,
	_ router.Metadata,
	builder audit.RuntimeV8Builder,
) (audit.RuntimeV8EmitOutcome, error) {
	record, err := builder(audit.RuntimeV8BuildContext{
		ConfigGeneration: 1,
		ConfigDigest:     strings.Repeat("a", 64),
	}, router.AdmissionOrdinary)
	if err != nil {
		return audit.RuntimeV8EmitOutcome{}, err
	}
	capture.records = append(capture.records, record.Clone())
	return audit.RuntimeV8EmitOutcome{
		Admission: router.AdmissionOrdinary, LocalPersisted: true,
	}, nil
}

func newNativeSkillRuntimeTestStore(
	t *testing.T,
) (*audit.Store, *audit.Logger) {
	t.Helper()
	store, err := audit.NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	return store, audit.NewLogger(store)
}

func invokeNativeSkillHook(
	t *testing.T, api *APIServer, connector, rawPayload string,
) nativeSkillHookResponse {
	t.Helper()
	if strings.Contains(rawPayload, "skill_name") {
		t.Fatal("fixture must use the connector-native payload, not synthetic skill_name")
	}
	hookPath := "/api/v1/" + connector + "/hook"
	if connector == "claudecode" {
		hookPath = "/api/v1/claude-code/hook"
	}
	req := httptest.NewRequest(
		http.MethodPost, hookPath,
		strings.NewReader(rawPayload),
	)
	recorder := httptest.NewRecorder()
	api.handleAgentHook(connector)(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("hook status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	var response nativeSkillHookResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode hook response: %v body=%s", err, recorder.Body.String())
	}
	return response
}

func TestCodexNativePromptSelectionHonorsScopedRuntimeDisable(t *testing.T) {
	store, logger := newNativeSkillRuntimeTestStore(t)
	if err := store.SetActionFieldForConnector(
		"skill", "review-pr", "codex", "runtime", "disable", "fixture",
	); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Guardrail.Connector = "codex"
	cfg.Guardrail.Mode = "action"
	api := &APIServer{store: store, logger: logger, scannerCfg: cfg}

	response := invokeNativeSkillHook(t, api, "codex", `{
		"hook_event_name":"UserPromptSubmit",
		"session_id":"fresh-codex-session",
		"turn_id":"turn-1",
		"prompt":"$review-pr inspect this change"
	}`)
	if response.Action != "block" || response.RawAction != "block" {
		t.Fatalf("action=%q raw=%q reason=%q", response.Action, response.RawAction, response.Reason)
	}
	if response.CodexOutput["decision"] != "block" {
		t.Fatalf("codex output = %#v, want decision=block", response.CodexOutput)
	}
	state, err := store.GetRuntimeAssetState(
		context.Background(), "codex", "fresh-codex-session", "skill", "review-pr",
	)
	if err != nil {
		t.Fatal(err)
	}
	if state == nil || state.State != audit.RuntimeAssetBlocked ||
		state.Provenance != runtimeProvenanceCodexPromptSelection ||
		state.RuntimeSurface != "prompt_selection" {
		t.Fatalf("runtime state = %#v", state)
	}
}

func TestCodexNativePromptSelectionFailsClosedWithoutProvenanceStore(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Connector = "codex"
	cfg.Guardrail.Mode = "action"
	api := &APIServer{scannerCfg: cfg}

	response := invokeNativeSkillHook(t, api, "codex", `{
		"hook_event_name":"UserPromptSubmit",
		"session_id":"fresh-codex-session",
		"prompt":"$review-pr inspect this change"
	}`)
	if response.Action != "block" || response.RawAction != "block" {
		t.Fatalf("action=%q raw=%q reason=%q", response.Action, response.RawAction, response.Reason)
	}
	if !strings.Contains(response.Reason, "reason_code=runtime-provenance-error") {
		t.Fatalf("reason=%q, want runtime provenance failure", response.Reason)
	}
}

func TestClaudeNativePromptExpansionHonorsScopedRuntimeDisable(t *testing.T) {
	store, logger := newNativeSkillRuntimeTestStore(t)
	if err := store.SetActionFieldForConnector(
		"skill", "review-pr", "claudecode", "runtime", "disable", "fixture",
	); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.Mode = "action"
	api := &APIServer{store: store, logger: logger, scannerCfg: cfg}

	response := invokeNativeSkillHook(t, api, "claudecode", `{
		"hook_event_name":"UserPromptExpansion",
		"session_id":"fresh-claude-session",
		"prompt":"/review-pr inspect this change",
		"expansion_type":"slash_command",
		"command_name":"review-pr",
		"command_args":"inspect this change",
		"command_source":"skill"
	}`)
	if response.Action != "block" || response.RawAction != "block" {
		t.Fatalf("action=%q raw=%q reason=%q", response.Action, response.RawAction, response.Reason)
	}
	if response.ClaudeCodeOutput["decision"] != "block" {
		t.Fatalf("claude output = %#v, want decision=block", response.ClaudeCodeOutput)
	}
	state, err := store.GetRuntimeAssetState(
		context.Background(), "claudecode", "fresh-claude-session", "skill", "review-pr",
	)
	if err != nil {
		t.Fatal(err)
	}
	if state == nil || state.State != audit.RuntimeAssetBlocked ||
		state.Provenance != runtimeProvenanceClaudeExpansion ||
		state.RuntimeSurface != "prompt_expansion" {
		t.Fatalf("runtime state = %#v", state)
	}
}

func TestClaudeNativePromptExpansionCorrelatesRuntimeDisableFromProductionIdentityVariants(t *testing.T) {
	installCorrelationHMACForTest()
	tests := []struct {
		name       string
		targetType string
		targetName string
		rawPayload string
	}{
		{
			name:       "userSettings source observed from filesystem skill",
			targetType: "skill",
			targetName: "dc-test-benign",
			rawPayload: `{
				"hook_event_name":"UserPromptExpansion",
				"session_id":"claude-user-settings-source",
				"prompt":"/dc-test-benign Greet Kevin without using tools.",
				"expansion_type":"slash_command",
				"command_name":"dc-test-benign",
				"command_args":"Greet Kevin without using tools.",
				"command_source":"userSettings",
				"prompt_id":"00000000-0000-0000-0000-000000000001"
			}`,
		},
		{
			name:       "projectSettings source with slash-prefixed command name",
			targetType: "skill",
			targetName: "dc-test-benign",
			rawPayload: `{
				"hook_event_name":"UserPromptExpansion",
				"session_id":"claude-project-source",
				"prompt":"/dc-test-benign Greet Kevin without using tools.",
				"expansion_type":"slash_command",
				"command_name":"/dc-test-benign",
				"command_args":"Greet Kevin without using tools.",
				"command_source":"projectSettings"
			}`,
		},
		{
			name:       "missing optional command metadata",
			targetType: "skill",
			targetName: "dc-test-benign",
			rawPayload: `{
				"hook_event_name":"UserPromptExpansion",
				"session_id":"claude-prompt-fallback",
				"prompt":"/dc-test-benign Greet Kevin without using tools."
			}`,
		},
		{
			name:       "conflicting identity cannot hide disabled prompt token",
			targetType: "skill",
			targetName: "dc-test-benign",
			rawPayload: `{
				"hook_event_name":"UserPromptExpansion",
				"session_id":"claude-mismatch",
				"prompt":"/dc-test-benign run",
				"expansion_type":"slash_command",
				"command_name":"different-skill",
				"command_source":"user"
			}`,
		},
		{
			name:       "conflicting identity cannot hide disabled command field",
			targetType: "skill",
			targetName: "dc-test-benign",
			rawPayload: `{
				"hook_event_name":"UserPromptExpansion",
				"session_id":"claude-inverse-mismatch",
				"prompt":"/different-skill run",
				"expansion_type":"slash_command",
				"command_name":"dc-test-benign",
				"command_source":"userSettings"
			}`,
		},
		{
			name:       "builtin provenance cannot override exact disabled identity",
			targetType: "skill",
			targetName: "dc-test-benign",
			rawPayload: `{
				"hook_event_name":"UserPromptExpansion",
				"session_id":"claude-builtin-spoof",
				"prompt":"/dc-test-benign run",
				"expansion_type":"slash_command",
				"command_name":"dc-test-benign",
				"command_source":"builtin"
			}`,
		},
		{
			name:       "namespaced plugin command resolves to canonical plugin",
			targetType: "plugin",
			targetName: "example-plugin",
			rawPayload: `{
				"hook_event_name":"UserPromptExpansion",
				"session_id":"claude-plugin-namespace",
				"prompt":"/example-plugin:run-diagnostics audit-canary",
				"expansion_type":"slash_command",
				"command_name":"example-plugin:run-diagnostics",
				"command_args":"audit-canary",
				"command_source":"plugin"
			}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store, logger := newNativeSkillRuntimeTestStore(t)
			auditCapture := &nativeSkillRuntimeAuditCapture{}
			logger.SetRuntimeV8Emitter(auditCapture)
			if err := store.SetActionFieldForConnector(
				tc.targetType, tc.targetName, "claudecode", "runtime", "disable", "fixture",
			); err != nil {
				t.Fatal(err)
			}
			cfg := &config.Config{}
			cfg.Guardrail.Connector = "claudecode"
			cfg.Guardrail.Mode = "action"
			api := &APIServer{store: store, logger: logger, scannerCfg: cfg}

			response := invokeNativeSkillHook(t, api, "claudecode", tc.rawPayload)
			if response.Action != "block" || response.RawAction != "block" {
				t.Fatalf("action=%q raw=%q reason=%q", response.Action, response.RawAction, response.Reason)
			}
			for _, want := range []string{
				"reason_code=runtime-disable",
				"source=runtime-disable",
				"asset_type=" + tc.targetType,
				"asset_name=" + tc.targetName,
				"connector=claudecode",
				"surface=prompt_expansion",
			} {
				if !strings.Contains(response.Reason, want) {
					t.Fatalf("reason %q missing %q", response.Reason, want)
				}
			}

			hookIndexes := make([]int, 0, 1)
			for i := range auditCapture.records {
				if auditCapture.records[i].Action() == string(audit.ActionConnectorHook) {
					hookIndexes = append(hookIndexes, i)
				}
			}
			if len(hookIndexes) != 1 {
				t.Fatalf("connector-hook records=%d records=%#v, want exactly one", len(hookIndexes), auditCapture.records)
			}
			allRecordPayload, err := json.Marshal(auditCapture.records)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{
				"Greet Kevin without using tools.", "audit-canary",
			} {
				if strings.Contains(string(allRecordPayload), forbidden) {
					t.Fatalf("runtime audit records leaked prompt/argument canary %q", forbidden)
				}
			}
			recordPayload, err := json.Marshal(auditCapture.records[hookIndexes[0]])
			if err != nil {
				t.Fatal(err)
			}
			var recordMap map[string]interface{}
			if err := json.Unmarshal(recordPayload, &recordMap); err != nil {
				t.Fatal(err)
			}
			body, _ := recordMap["body"].(map[string]interface{})
			structuredJSON, _ := body["structured_json"].(string)
			var structured map[string]interface{}
			if err := json.Unmarshal([]byte(structuredJSON), &structured); err != nil {
				t.Fatalf("decode emitted connector-hook structured payload: %v payload=%q", err, structuredJSON)
			}
			if structured["connector"] != "claudecode" || structured["enforced"] != true {
				t.Fatalf("audit connector=%v enforced=%v", structured["connector"], structured["enforced"])
			}
			if structured["event"] != "UserPromptExpansion" {
				t.Fatalf("audit event=%v, want UserPromptExpansion", structured["event"])
			}
			if structured["action"] != "block" || structured["raw_action"] != "block" {
				t.Fatalf("audit action=%v raw_action=%v", structured["action"], structured["raw_action"])
			}
			auditReason, _ := structured["reason"].(string)
			if !strings.Contains(auditReason, "reason_code=runtime-disable") {
				t.Fatalf("audit reason=%q, want runtime-disable provenance", auditReason)
			}
		})
	}
}

func TestClaudeFilesystemSkillProvenanceMapsToRuntimeDisableSkillNamespace(t *testing.T) {
	for _, source := range []string{
		"skill", "policySettings", "userSettings", "projectSettings", "bundled",
	} {
		t.Run(source, func(t *testing.T) {
			if got := slashCommandAssetType(source); got != "skill" {
				t.Fatalf("slashCommandAssetType(%q)=%q, want skill", source, got)
			}
		})
	}
	if got := slashCommandAssetType("plugin"); got != "plugin" {
		t.Fatalf("slashCommandAssetType(plugin)=%q, want plugin", got)
	}
	for _, source := range []string{"skill", "plugin"} {
		if !claudeCodeSlashSourceTrustsAssetPolicy(source) {
			t.Fatalf("source %q must retain full asset-policy handling", source)
		}
	}
	for _, source := range []string{
		"policySettings", "userSettings", "projectSettings", "bundled",
	} {
		if claudeCodeSlashSourceTrustsAssetPolicy(source) {
			t.Fatalf("settings source %q must remain runtime-disable-only", source)
		}
	}
	for _, source := range []string{"builtin", "user", "project", "unknown"} {
		if got := slashCommandAssetType(source); got != "" {
			t.Fatalf("slashCommandAssetType(%q)=%q, want ambiguous/unattributed", source, got)
		}
	}
}

func TestClaudeSettingsOriginCustomCommandDoesNotEnterFullSkillPolicy(t *testing.T) {
	for _, source := range []string{
		"policySettings", "userSettings", "projectSettings", "bundled",
	} {
		t.Run(source, func(t *testing.T) {
			store, logger := newNativeSkillRuntimeTestStore(t)
			cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
			cfg.Guardrail.Connector = "claudecode"
			cfg.Guardrail.Mode = "action"
			cfg.AssetPolicy.Enabled = true
			cfg.AssetPolicy.Mode = "action"
			cfg.AssetPolicy.Skill.RegistryRequired = true
			enableSkillRuntimeDetection(cfg)
			api := &APIServer{store: store, logger: logger, scannerCfg: cfg}

			payload, err := json.Marshal(map[string]interface{}{
				"hook_event_name": "UserPromptExpansion",
				"session_id":      "settings-custom-" + strings.ToLower(source),
				"prompt":          "/ordinary-command run",
				"expansion_type":  "slash_command",
				"command_name":    "ordinary-command",
				"command_source":  source,
			})
			if err != nil {
				t.Fatal(err)
			}
			response := invokeNativeSkillHook(t, api, "claudecode", string(payload))
			if response.Action != "allow" || response.RawAction != "allow" {
				t.Fatalf(
					"action=%q raw=%q reason=%q, settings-origin custom command entered full skill policy",
					response.Action, response.RawAction, response.Reason,
				)
			}
			if strings.Contains(response.Reason, "ASSET-POLICY-SKILL") ||
				strings.Contains(response.Reason, "registry-required") {
				t.Fatalf("reason=%q incorrectly attributed custom command to skill policy", response.Reason)
			}
			state, err := store.GetRuntimeAssetState(
				context.Background(), "claudecode", "settings-custom-"+strings.ToLower(source),
				"skill", "ordinary-command",
			)
			if err != nil {
				t.Fatal(err)
			}
			if state != nil {
				t.Fatalf("runtime state=%#v, unmatched custom command was attributed as a skill", state)
			}
		})
	}
}

func TestClaudeUnknownCommandSourceIsNotPersistedOrReturned(t *testing.T) {
	const secretSource = "credential-like-source-value"
	store, logger := newNativeSkillRuntimeTestStore(t)
	auditCapture := &nativeSkillRuntimeAuditCapture{}
	logger.SetRuntimeV8Emitter(auditCapture)
	if err := store.SetActionFieldForConnector(
		"skill", "dc-test-benign", "claudecode", "runtime", "disable", "fixture",
	); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.Mode = "action"
	api := &APIServer{store: store, logger: logger, scannerCfg: cfg}

	payload, err := json.Marshal(map[string]interface{}{
		"hook_event_name": "UserPromptExpansion",
		"session_id":      "claude-secret-source",
		"prompt":          "/dc-test-benign run",
		"expansion_type":  "slash_command",
		"command_name":    "dc-test-benign",
		"command_source":  secretSource,
	})
	if err != nil {
		t.Fatal(err)
	}
	response := invokeNativeSkillHook(t, api, "claudecode", string(payload))
	if response.Action != "block" || response.RawAction != "block" {
		t.Fatalf("action=%q raw=%q reason=%q, want runtime-disable block", response.Action, response.RawAction, response.Reason)
	}
	if strings.Contains(response.Reason, secretSource) {
		t.Fatalf("response reason leaked untrusted command source: %q", response.Reason)
	}
	auditPayload, err := json.Marshal(auditCapture.records)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(auditPayload), secretSource) {
		t.Fatalf("runtime audit records leaked untrusted command source")
	}
	state, err := store.GetRuntimeAssetState(
		context.Background(), "claudecode", "claude-secret-source", "skill", "dc-test-benign",
	)
	if err != nil {
		t.Fatal(err)
	}
	if state == nil || state.State != audit.RuntimeAssetBlocked {
		t.Fatalf("runtime state=%#v, want blocked runtime-disable provenance", state)
	}
	if state.SourcePath != "" || strings.Contains(state.SourcePath, secretSource) {
		t.Fatalf("runtime source_path=%q, want unrecognized source discarded", state.SourcePath)
	}
}

func TestClaudeNativePromptExpansionDoesNotMisattributeAmbiguousOrNonSkillInput(t *testing.T) {
	tests := []struct {
		name       string
		sessionID  string
		rawPayload string
		assetNames []string
	}{
		{
			name:      "path-shaped identity",
			sessionID: "claude-path-shaped",
			rawPayload: `{
				"hook_event_name":"UserPromptExpansion",
				"session_id":"claude-path-shaped",
				"prompt":"/../dc-test-benign run",
				"expansion_type":"slash_command",
				"command_name":"../dc-test-benign",
				"command_source":"user"
			}`,
			assetNames: []string{"dc-test-benign"},
		},
		{
			name:      "plugin namespace is not a standalone skill alias",
			sessionID: "claude-plugin-namespace",
			rawPayload: `{
				"hook_event_name":"UserPromptExpansion",
				"session_id":"claude-plugin-namespace",
				"prompt":"/example-plugin:dc-test-benign run",
				"expansion_type":"slash_command",
				"command_name":"example-plugin:dc-test-benign",
				"command_source":"user"
			}`,
			assetNames: []string{"dc-test-benign"},
		},
		{
			name:      "conflicting identities without a disabled candidate",
			sessionID: "claude-unblocked-mismatch",
			rawPayload: `{
				"hook_event_name":"UserPromptExpansion",
				"session_id":"claude-unblocked-mismatch",
				"prompt":"/different-prompt-skill run",
				"expansion_type":"slash_command",
				"command_name":"different-command-skill",
				"command_source":"user"
			}`,
			assetNames: []string{"dc-test-benign", "different-prompt-skill", "different-command-skill"},
		},
		{
			name:      "encoded identity is not canonicalized",
			sessionID: "claude-encoded",
			rawPayload: `{
				"hook_event_name":"UserPromptExpansion",
				"session_id":"claude-encoded",
				"prompt":"/%64c-test-benign run",
				"expansion_type":"slash_command",
				"command_name":"%64c-test-benign",
				"command_source":"project"
			}`,
			assetNames: []string{"dc-test-benign"},
		},
		{
			name:      "non-skill expansion",
			sessionID: "claude-mcp-prompt",
			rawPayload: `{
				"hook_event_name":"UserPromptExpansion",
				"session_id":"claude-mcp-prompt",
				"prompt":"ordinary prompt",
				"expansion_type":"mcp_prompt",
				"command_name":"unrelated-server",
				"command_source":"unrelated-server"
			}`,
			assetNames: []string{"dc-test-benign"},
		},
		{
			name:      "builtin slash command is a distinct asset",
			sessionID: "claude-builtin",
			rawPayload: `{
				"hook_event_name":"UserPromptExpansion",
				"session_id":"claude-builtin",
				"prompt":"/help",
				"expansion_type":"slash_command",
				"command_name":"help",
				"command_source":"builtin"
			}`,
			assetNames: []string{"dc-test-benign"},
		},
		{
			name:      "unrelated prompt",
			sessionID: "claude-unrelated",
			rawPayload: `{
				"hook_event_name":"UserPromptExpansion",
				"session_id":"claude-unrelated",
				"prompt":"ordinary text mentioning dc-test-benign"
			}`,
			assetNames: []string{"dc-test-benign"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store, logger := newNativeSkillRuntimeTestStore(t)
			if err := store.SetActionFieldForConnector(
				"skill", "dc-test-benign", "claudecode", "runtime", "disable", "fixture",
			); err != nil {
				t.Fatal(err)
			}
			cfg := &config.Config{}
			cfg.Guardrail.Connector = "claudecode"
			cfg.Guardrail.Mode = "action"
			api := &APIServer{store: store, logger: logger, scannerCfg: cfg}

			response := invokeNativeSkillHook(t, api, "claudecode", tc.rawPayload)
			if response.Action != "allow" || response.RawAction != "allow" {
				t.Fatalf("action=%q raw=%q reason=%q, want unrelated input allowed", response.Action, response.RawAction, response.Reason)
			}
			for _, assetName := range tc.assetNames {
				state, err := store.GetRuntimeAssetState(
					context.Background(), "claudecode", tc.sessionID, "skill", assetName,
				)
				if err != nil {
					t.Fatal(err)
				}
				if state != nil {
					t.Fatalf("runtime state=%#v, malformed/non-skill input was incorrectly attributed", state)
				}
			}
		})
	}
}

func TestClaudeKnownSkillExpansionMalformedIdentityFailsClosedWithoutRawValues(t *testing.T) {
	tests := []struct {
		name       string
		rawPayload string
	}{
		{
			name: "missing command identity",
			rawPayload: `{
				"hook_event_name":"UserPromptExpansion",
				"session_id":"claude-missing-command",
				"prompt":"/otherwise-valid secret-marker",
				"expansion_type":"slash_command",
				"command_source":"skill"
			}`,
		},
		{
			name: "unsafe command identity",
			rawPayload: `{
				"hook_event_name":"UserPromptExpansion",
				"session_id":"claude-unsafe-command",
				"prompt":"/../unsafe-skill secret-marker",
				"expansion_type":"slash_command",
				"command_name":"../unsafe-skill",
				"command_source":"skill"
			}`,
		},
		{
			name: "trusted skill metadata without slash prompt",
			rawPayload: `{
				"hook_event_name":"UserPromptExpansion",
				"session_id":"claude-missing-slash-prompt",
				"prompt":"ordinary text secret-marker",
				"expansion_type":"slash_command",
				"command_name":"otherwise-valid",
				"command_source":"skill"
			}`,
		},
		{
			name: "conflicting known skill identities",
			rawPayload: `{
				"hook_event_name":"UserPromptExpansion",
				"session_id":"claude-known-mismatch",
				"prompt":"/prompt-candidate secret-marker",
				"expansion_type":"slash_command",
				"command_name":"command-candidate",
				"command_source":"skill"
			}`,
		},
		{
			name: "plugin whitespace around namespace separator",
			rawPayload: `{
				"hook_event_name":"UserPromptExpansion",
				"session_id":"claude-plugin-whitespace",
				"prompt":"/plugin-id:command-id secret-marker",
				"expansion_type":"slash_command",
				"command_name":"plugin-id : command-id",
				"command_source":"plugin"
			}`,
		},
		{
			name: "plugin bare and namespaced identities disagree",
			rawPayload: `{
				"hook_event_name":"UserPromptExpansion",
				"session_id":"claude-plugin-asymmetric",
				"prompt":"/plugin-id:command-id secret-marker",
				"expansion_type":"slash_command",
				"command_name":"plugin-id",
				"command_source":"plugin"
			}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store, logger := newNativeSkillRuntimeTestStore(t)
			cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
			cfg.Guardrail.Connector = "claudecode"
			cfg.Guardrail.Mode = "action"
			cfg.AssetPolicy.Enabled = true
			cfg.AssetPolicy.Mode = "action"
			api := &APIServer{store: store, logger: logger, scannerCfg: cfg}

			response := invokeNativeSkillHook(t, api, "claudecode", tc.rawPayload)
			if response.Action != "block" || response.RawAction != "block" {
				t.Fatalf("action=%q raw=%q reason=%q, want fail-closed block", response.Action, response.RawAction, response.Reason)
			}
			if !strings.Contains(response.Reason, "reason_code=runtime-identity-error") {
				t.Fatalf("reason=%q, want sanitized identity-error provenance", response.Reason)
			}
			for _, forbidden := range []string{"secret-marker", "../unsafe-skill"} {
				if strings.Contains(response.Reason, forbidden) {
					t.Fatalf("reason=%q leaked raw value %q", response.Reason, forbidden)
				}
			}
		})
	}
}

func TestClaudeKnownSkillMalformedIdentityHonorsObserveMode(t *testing.T) {
	store, logger := newNativeSkillRuntimeTestStore(t)
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.Mode = "observe"
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = "observe"
	api := &APIServer{store: store, logger: logger, scannerCfg: cfg}

	response := invokeNativeSkillHook(t, api, "claudecode", `{
		"hook_event_name":"UserPromptExpansion",
		"session_id":"claude-observe-mismatch",
		"prompt":"/prompt-candidate secret-marker",
		"expansion_type":"slash_command",
		"command_name":"command-candidate",
		"command_source":"skill"
	}`)
	if response.Action != "allow" || response.RawAction != "block" {
		t.Fatalf("action=%q raw=%q reason=%q, want observe allow/raw-block", response.Action, response.RawAction, response.Reason)
	}
	if !strings.Contains(response.Reason, "reason_code=runtime-identity-error") {
		t.Fatalf("reason=%q, want sanitized identity-error provenance", response.Reason)
	}
	if strings.Contains(response.Reason, "secret-marker") {
		t.Fatalf("observe reason leaked raw prompt content: %q", response.Reason)
	}
}

func TestNativePromptRuntimeDisableScopeGlobalAndReenableLifecycle(t *testing.T) {
	store, logger := newNativeSkillRuntimeTestStore(t)
	apiFor := func(connector string) *APIServer {
		cfg := &config.Config{}
		cfg.Guardrail.Connector = connector
		cfg.Guardrail.Mode = "action"
		return &APIServer{store: store, logger: logger, scannerCfg: cfg}
	}
	claudeAPI := apiFor("claudecode")
	codexAPI := apiFor("codex")
	invokeClaude := func() nativeSkillHookResponse {
		return invokeNativeSkillHook(t, claudeAPI, "claudecode", `{
			"hook_event_name":"UserPromptExpansion",
			"session_id":"scope-claude",
			"prompt":"/dc-test-benign run",
			"expansion_type":"slash_command",
			"command_name":"dc-test-benign",
			"command_source":"userSettings"
		}`)
	}
	invokeCodex := func() nativeSkillHookResponse {
		return invokeNativeSkillHook(t, codexAPI, "codex", `{
			"hook_event_name":"UserPromptSubmit",
			"session_id":"scope-codex",
			"prompt":"$dc-test-benign run"
		}`)
	}
	assertAction := func(label string, response nativeSkillHookResponse, want string) {
		t.Helper()
		if response.Action != want || response.RawAction != want {
			t.Fatalf("%s action=%q raw=%q reason=%q, want %s", label, response.Action, response.RawAction, response.Reason, want)
		}
	}

	if err := store.SetActionFieldForConnector(
		"skill", "dc-test-benign", "claudecode", "runtime", "disable", "fixture",
	); err != nil {
		t.Fatal(err)
	}
	assertAction("Claude scoped disable", invokeClaude(), "block")
	assertAction("Claude scoped peer", invokeCodex(), "allow")
	if err := store.ClearActionFieldForConnector(
		"skill", "dc-test-benign", "claudecode", "runtime",
	); err != nil {
		t.Fatal(err)
	}
	assertAction("Claude re-enable", invokeClaude(), "allow")

	if err := store.SetActionFieldForConnector(
		"skill", "dc-test-benign", "codex", "runtime", "disable", "fixture",
	); err != nil {
		t.Fatal(err)
	}
	assertAction("Codex scoped disable", invokeCodex(), "block")
	assertAction("Codex scoped peer", invokeClaude(), "allow")
	if err := store.ClearActionFieldForConnector(
		"skill", "dc-test-benign", "codex", "runtime",
	); err != nil {
		t.Fatal(err)
	}
	assertAction("Codex re-enable", invokeCodex(), "allow")

	if err := store.SetActionField(
		"skill", "dc-test-benign", "runtime", "disable", "fixture",
	); err != nil {
		t.Fatal(err)
	}
	assertAction("global Claude disable", invokeClaude(), "block")
	assertAction("global Codex disable", invokeCodex(), "block")
	if err := store.ClearActionField("skill", "dc-test-benign", "runtime"); err != nil {
		t.Fatal(err)
	}
	assertAction("global Claude re-enable", invokeClaude(), "allow")
	assertAction("global Codex re-enable", invokeCodex(), "allow")
}

func TestClaudeNativePromptExpansionFailsClosedWithoutProvenanceStore(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.Mode = "action"
	api := &APIServer{scannerCfg: cfg}

	response := invokeNativeSkillHook(t, api, "claudecode", `{
		"hook_event_name":"UserPromptExpansion",
		"session_id":"fresh-claude-session",
		"prompt":"/review-pr inspect this change",
		"expansion_type":"slash_command",
		"command_name":"review-pr",
		"command_args":"inspect this change",
		"command_source":"skill"
	}`)
	if response.Action != "block" || response.RawAction != "block" {
		t.Fatalf("action=%q raw=%q reason=%q", response.Action, response.RawAction, response.Reason)
	}
	if !strings.Contains(response.Reason, "reason_code=runtime-provenance-error") {
		t.Fatalf("reason=%q, want runtime provenance failure", response.Reason)
	}
}

func TestClaudeSettingsOriginPromptExpansionFailsClosedWithoutProvenanceStore(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.Mode = "action"
	api := &APIServer{scannerCfg: cfg}

	response := invokeNativeSkillHook(t, api, "claudecode", `{
		"hook_event_name":"UserPromptExpansion",
		"session_id":"settings-no-store",
		"prompt":"/review-pr inspect this change",
		"expansion_type":"slash_command",
		"command_name":"review-pr",
		"command_args":"inspect this change",
		"command_source":"userSettings"
	}`)
	if response.Action != "block" || response.RawAction != "block" {
		t.Fatalf("action=%q raw=%q reason=%q", response.Action, response.RawAction, response.Reason)
	}
	if !strings.Contains(response.Reason, "reason_code=runtime-provenance-error") {
		t.Fatalf("reason=%q, want runtime provenance failure", response.Reason)
	}
}

func TestNativeSkillSelectionWriteFailureFailsClosedUnlessStrongerBlock(t *testing.T) {
	tests := []struct {
		name               string
		disable            bool
		wantSource         string
		wantReasonContains string
	}{
		{
			name:               "selection without stronger block",
			wantSource:         "runtime-provenance-error",
			wantReasonContains: "runtime provenance write failed",
		},
		{
			name:       "existing runtime disable remains authoritative",
			disable:    true,
			wantSource: "runtime-disable",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, _ := newNativeSkillRuntimeTestStore(t)
			if test.disable {
				if err := store.SetActionFieldForConnector(
					"skill", "review-pr", "claudecode", "runtime", "disable", "fixture",
				); err != nil {
					t.Fatal(err)
				}
			}
			api := &APIServer{store: store}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			decision, matched := api.evaluateNativeRuntimeSkillSelection(
				ctx, "claudecode", "write-failure-session",
				"UserPromptExpansion", runtimeProvenanceClaudeExpansion,
				skillRuntimeProbe{
					TargetType: "skill", SkillName: "review-pr",
					SourcePath: "skill", Surface: "prompt_expansion", Matched: true,
				},
			)
			if !matched || decision.Action != "block" || decision.RawAction != "block" {
				t.Fatalf("decision=%#v matched=%t, want enforced block", decision, matched)
			}
			if decision.Source != test.wantSource {
				t.Fatalf("source=%q, want %q", decision.Source, test.wantSource)
			}
			if test.wantReasonContains != "" && !strings.Contains(decision.Reason, test.wantReasonContains) {
				t.Fatalf("reason=%q, want %q", decision.Reason, test.wantReasonContains)
			}
			state, err := store.GetRuntimeAssetState(
				context.Background(), "claudecode", "write-failure-session", "skill", "review-pr",
			)
			if err != nil {
				t.Fatal(err)
			}
			if state != nil {
				t.Fatalf("runtime state = %#v, canceled write must not persist", state)
			}
		})
	}
}

func TestClaudeNativePromptExpansionRecordsLoadedAttestation(t *testing.T) {
	store, logger := newNativeSkillRuntimeTestStore(t)
	api := &APIServer{store: store, logger: logger}

	decision, matched := api.evaluateNativeRuntimeSkillSelection(
		context.Background(), "claudecode", "loaded-session",
		"UserPromptExpansion", runtimeProvenanceClaudeExpansion,
		skillRuntimeProbe{
			TargetType: "skill", SkillName: "review-pr",
			SourcePath: "skill", Surface: "prompt_expansion", Matched: true,
		},
	)
	if matched || decision.Action != "" {
		t.Fatalf("unexpected policy decision = %#v matched=%t", decision, matched)
	}
	state, err := store.GetRuntimeAssetState(
		context.Background(), "claudecode", "loaded-session", "skill", "review-pr",
	)
	if err != nil {
		t.Fatal(err)
	}
	if state == nil || state.State != audit.RuntimeAssetLoaded ||
		state.Provenance != runtimeProvenanceClaudeExpansion {
		t.Fatalf("runtime state = %#v, want loaded expansion attestation", state)
	}
}

func TestCodexNativePromptRemainsSelectionAttestation(t *testing.T) {
	store, logger := newNativeSkillRuntimeTestStore(t)
	api := &APIServer{store: store, logger: logger}

	_, _ = api.evaluateNativeRuntimeSkillSelection(
		context.Background(), "codex", "selected-session",
		"UserPromptSubmit", runtimeProvenanceCodexPromptSelection,
		skillRuntimeProbe{
			TargetType: "skill", SkillName: "review-pr",
			Surface: "prompt_selection", Matched: true,
		},
	)
	state, err := store.GetRuntimeAssetState(
		context.Background(), "codex", "selected-session", "skill", "review-pr",
	)
	if err != nil {
		t.Fatal(err)
	}
	if state == nil || state.State != audit.RuntimeAssetSelected {
		t.Fatalf("runtime state = %#v, want selected attestation", state)
	}
}
