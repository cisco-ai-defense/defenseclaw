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
)

type nativeSkillHookResponse struct {
	Action           string                 `json:"action"`
	RawAction        string                 `json:"raw_action"`
	Reason           string                 `json:"reason"`
	CodexOutput      map[string]interface{} `json:"codex_output"`
	ClaudeCodeOutput map[string]interface{} `json:"claude_code_output"`
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
