// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// TestHookAIDInspect_GateBehavior covers the four ways the AID lane
// silently no-ops: nil server, no inspector, ScanHookSurface=false,
// empty content. Each path returns nil and triggers no upstream call.
func TestHookAIDInspect_GateBehavior(t *testing.T) {
	t.Run("nil_inspector_returns_nil", func(t *testing.T) {
		a := &APIServer{scannerCfg: &config.Config{}}
		if v := a.hookAIDInspect("mcp__jira__createJiraIssue", "summary=test"); v != nil {
			t.Fatalf("expected nil when inspector unset, got %+v", v)
		}
	})

	t.Run("scan_hook_surface_false_returns_nil", func(t *testing.T) {
		falseFlag := false
		cfg := &config.Config{
			CiscoAIDefense: config.CiscoAIDefenseConfig{
				ScanHookSurface: &falseFlag,
			},
		}
		a := &APIServer{
			scannerCfg:     cfg,
			ciscoInspector: &CiscoInspectClient{apiKey: "any"}, // wired but disabled
		}
		if v := a.hookAIDInspect("mcp__jira__createJiraIssue", "x"); v != nil {
			t.Fatalf("expected nil when ScanHookSurface=false, got %+v", v)
		}
	})

	t.Run("empty_content_returns_nil", func(t *testing.T) {
		a := &APIServer{
			scannerCfg:     &config.Config{},
			ciscoInspector: &CiscoInspectClient{apiKey: "any"},
		}
		if v := a.hookAIDInspect("mcp__jira__createJiraIssue", ""); v != nil {
			t.Fatalf("expected nil for empty content, got %+v", v)
		}
	})
}

func TestHandleAgentHook_AIDAppliesAcrossHookProfiles(t *testing.T) {
	cases := []struct {
		connector string
		path      string
		event     string
	}{
		{"codex", "/api/v1/codex/hook", "PreToolUse"},
		{"claudecode", "/api/v1/claude-code/hook", "PreToolUse"},
		{"cursor", "/api/v1/cursor/hook", "beforeShellExecution"},
		{"geminicli", "/api/v1/geminicli/hook", "BeforeTool"},
		{"hermes", "/api/v1/hermes/hook", "pre_tool_call"},
		{"windsurf", "/api/v1/windsurf/hook", "pre_run_command"},
		{"copilot", "/api/v1/copilot/hook", "PreToolUse"},
		{"openhands", "/api/v1/openhands/hook", "PreToolUse"},
	}

	for _, tc := range cases {
		t.Run(tc.connector, func(t *testing.T) {
			var calls int
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{
					"is_safe": false,
					"action": "Block",
					"rules": [{"rule_name":"AID hook contract","classification":"VIOLATION"}],
					"processed_rules": [{"rule_name":"AID hook contract"}]
				}`))
			}))
			defer srv.Close()

			api := &APIServer{
				scannerCfg: &config.Config{
					Guardrail: config.GuardrailConfig{
						Connector: tc.connector,
						Mode:      "action",
					},
				},
				ciscoInspector: &CiscoInspectClient{
					apiKey:   "test-key",
					endpoint: srv.URL,
					client:   srv.Client(),
				},
			}
			body, err := json.Marshal(map[string]interface{}{
				"hook_event_name": tc.event,
				"session_id":      "sess-aid-" + tc.connector,
				"turn_id":         "turn-aid-" + tc.connector,
				"tool_name":       "safeTool",
				"tool_use_id":     "tool-aid-" + tc.connector,
				"tool_input":      map[string]interface{}{"value": "ordinary payload"},
			})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			req := httptest.NewRequest(http.MethodPost, tc.path, bytes.NewReader(body))
			w := httptest.NewRecorder()
			api.handleAgentHook(tc.connector).ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			if calls == 0 {
				t.Fatalf("expected AID lane to be called for %s", tc.connector)
			}
			var got map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if got["action"] != "block" {
				t.Fatalf("%s action=%v want block body=%s", tc.connector, got["action"], w.Body.String())
			}
			findings, _ := got["findings"].([]interface{})
			hasAID := false
			for _, f := range findings {
				if s, _ := f.(string); strings.HasPrefix(s, "ai-defense:") {
					hasAID = true
				}
			}
			if !hasAID {
				t.Fatalf("%s response missing ai-defense finding: %s", tc.connector, w.Body.String())
			}
		})
	}
}

// TestHookAIDInspect_DefaultsToEnabledWhenKeyPresent ensures an
// operator who only sets api_key_env (no ScanHookSurface override)
// gets the lane enabled — the documented default.
func TestHookAIDInspect_DefaultsToEnabledWhenKeyPresent(t *testing.T) {
	cfg := &config.Config{
		CiscoAIDefense: config.CiscoAIDefenseConfig{
			APIKeyEnv: "DC_TEST_AID_KEY",
		},
	}
	if !cfg.CiscoAIDefense.HookSurfaceEnabled() {
		t.Fatal("HookSurfaceEnabled() should default to true when ScanHookSurface is unset")
	}
}

// TestHookAIDInspect_PrependsToolName verifies the tool name is woven
// into the AID payload so AID classifiers that match on tool-name
// strings (e.g. "Limit JIRA actions" / "createJiraIssue") see it.
func TestHookAIDInspect_PrependsToolName(t *testing.T) {
	var captured map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&captured)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"is_safe":true,"action":"Allow","rules":[],"processed_rules":[]}`))
	}))
	defer srv.Close()

	cisco := &CiscoInspectClient{
		apiKey:   "test-key",
		endpoint: srv.URL,
		client:   srv.Client(),
	}
	a := &APIServer{
		scannerCfg:     &config.Config{},
		ciscoInspector: cisco,
	}
	_ = a.hookAIDInspect("mcp__jira__createJiraIssue", `{"summary":"test"}`)

	msgs, _ := captured["messages"].([]interface{})
	if len(msgs) == 0 {
		t.Fatalf("expected at least one message in AID payload, got %+v", captured)
	}
	first, _ := msgs[0].(map[string]interface{})
	content, _ := first["content"].(string)
	if !strings.Contains(content, "mcp__jira__createJiraIssue") {
		t.Errorf("AID payload content should contain tool name; got %q", content)
	}
}

// TestMergeWithAIDVerdict_StrictestWins covers action escalation,
// severity escalation, and findings concatenation in the merge
// helper used by the hook-lane callers.
func TestMergeWithAIDVerdict_StrictestWins(t *testing.T) {
	t.Run("aid_block_escalates_local_alert", func(t *testing.T) {
		local := &ToolInspectVerdict{Action: "alert", Severity: "MEDIUM"}
		aid := &ScanVerdict{Action: "block", Severity: "HIGH", Findings: []string{"jira-policy"}, Reason: "AID rule fired"}
		merged := mergeWithAIDVerdict(local, aid)
		if merged.Action != "block" {
			t.Errorf("expected block, got %q", merged.Action)
		}
		if merged.Severity != "HIGH" {
			t.Errorf("expected HIGH, got %q", merged.Severity)
		}
		if len(merged.Findings) == 0 || !strings.HasPrefix(merged.Findings[0], "ai-defense:") {
			t.Errorf("expected ai-defense-prefixed finding, got %v", merged.Findings)
		}
	})

	t.Run("aid_allow_does_not_downgrade_local_block", func(t *testing.T) {
		local := &ToolInspectVerdict{Action: "block", Severity: "CRITICAL"}
		aid := &ScanVerdict{Action: "allow", Severity: "NONE"}
		merged := mergeWithAIDVerdict(local, aid)
		if merged.Action != "block" {
			t.Errorf("local block must not be downgraded by AID allow; got %q", merged.Action)
		}
		if merged.Severity != "CRITICAL" {
			t.Errorf("local CRITICAL must not be downgraded; got %q", merged.Severity)
		}
	})

	t.Run("nil_aid_returns_local_verbatim", func(t *testing.T) {
		local := &ToolInspectVerdict{Action: "alert", Severity: "MEDIUM"}
		if got := mergeWithAIDVerdict(local, nil); got != local {
			t.Errorf("nil AID should return local verbatim")
		}
	})

	t.Run("nil_local_with_aid_block_creates_block_verdict", func(t *testing.T) {
		aid := &ScanVerdict{Action: "block", Severity: "HIGH", Findings: []string{"r1"}, Reason: "AID"}
		merged := mergeWithAIDVerdict(nil, aid)
		if merged.Action != "block" {
			t.Errorf("expected block, got %q", merged.Action)
		}
	})
}

// TestMergeWithLaneVerdict_SynthesizesDetailedFindings pins the fix for
// the IPC total_scans stat: the AID / LLM-judge lanes only populate the
// stringy verdict.Findings slice, so before this synthesis step
// emitInspectVerdictFindings early-returned on empty DetailedFindings and
// no scan_results row was ever written for a managed_enterprise hook
// inspection — total_scans stayed at 0 even though every hook call ran
// an inspection. The merge helper must synthesize one DetailedFinding
// per lane finding so the downstream pipeline persists a scan row.
func TestMergeWithLaneVerdict_SynthesizesDetailedFindings(t *testing.T) {
	t.Run("aid_findings_become_detailed_findings", func(t *testing.T) {
		aid := &ScanVerdict{
			Action:   "block",
			Severity: "HIGH",
			Findings: []string{"pii.email", "policy.jira"},
		}
		merged := mergeWithAIDVerdict(nil, aid)
		if len(merged.DetailedFindings) != 2 {
			t.Fatalf("DetailedFindings = %d, want 2 (one per AID finding)", len(merged.DetailedFindings))
		}
		got := merged.DetailedFindings[0]
		if got.RuleID != "ai-defense:pii.email" {
			t.Errorf("RuleID = %q, want ai-defense:pii.email", got.RuleID)
		}
		if got.Title != "pii.email" {
			t.Errorf("Title = %q, want pii.email", got.Title)
		}
		if got.Severity != "HIGH" {
			t.Errorf("Severity = %q, want HIGH (from verdict)", got.Severity)
		}
		if len(got.Tags) != 1 || got.Tags[0] != "ai-defense" {
			t.Errorf("Tags = %v, want [ai-defense]", got.Tags)
		}
	})

	t.Run("judge_findings_become_detailed_findings_with_judge_tag", func(t *testing.T) {
		judge := &ScanVerdict{
			Action:   "alert",
			Severity: "MEDIUM",
			Findings: []string{"prompt_injection"},
		}
		merged := mergeWithJudgeVerdict(nil, judge)
		if len(merged.DetailedFindings) != 1 {
			t.Fatalf("DetailedFindings = %d, want 1", len(merged.DetailedFindings))
		}
		if got := merged.DetailedFindings[0].RuleID; got != "llm-judge:prompt_injection" {
			t.Errorf("RuleID = %q, want llm-judge:prompt_injection", got)
		}
		if got := merged.DetailedFindings[0].Tags; len(got) != 1 || got[0] != "llm-judge" {
			t.Errorf("Tags = %v, want [llm-judge]", got)
		}
	})

	t.Run("no_findings_no_synthesis", func(t *testing.T) {
		aid := &ScanVerdict{Action: "block", Severity: "HIGH"}
		merged := mergeWithAIDVerdict(nil, aid)
		if len(merged.DetailedFindings) != 0 {
			t.Errorf("DetailedFindings = %d, want 0 when lane returned no findings", len(merged.DetailedFindings))
		}
	})

	t.Run("preserves_existing_detailed_findings", func(t *testing.T) {
		local := &ToolInspectVerdict{
			Action:   "alert",
			Severity: "MEDIUM",
			DetailedFindings: []RuleFinding{
				{RuleID: "LOCAL-1", Severity: "MEDIUM"},
			},
		}
		aid := &ScanVerdict{Action: "block", Severity: "HIGH", Findings: []string{"pii.email"}}
		merged := mergeWithAIDVerdict(local, aid)
		if len(merged.DetailedFindings) != 2 {
			t.Fatalf("DetailedFindings = %d, want 2 (local + synthesized)", len(merged.DetailedFindings))
		}
		if merged.DetailedFindings[0].RuleID != "LOCAL-1" {
			t.Errorf("local finding not preserved at head: %+v", merged.DetailedFindings)
		}
		if merged.DetailedFindings[1].RuleID != "ai-defense:pii.email" {
			t.Errorf("synthesized finding not appended: %+v", merged.DetailedFindings)
		}
	})
}

// TestInspectToolPolicy_AIDLaneFiresWhenLocalAllow drives the full
// inspectToolPolicy path end-to-end with no local-rule match,
// asserting that an AID Block escalates the verdict from allow to
// block. The complementary cases (no-op when AID disabled, AID call
// shape) are covered by the unit tests above.
func TestInspectToolPolicy_AIDLaneFiresWhenLocalAllow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"is_safe": false,
			"action": "Block",
			"rules": [{"rule_name":"Limit JIRA actions","classification":"VIOLATION"}],
			"processed_rules": [{"rule_name":"Limit JIRA actions"}]
		}`))
	}))
	defer srv.Close()

	a := &APIServer{
		scannerCfg: &config.Config{},
		ciscoInspector: &CiscoInspectClient{
			apiKey:   "test-key",
			endpoint: srv.URL,
			client:   srv.Client(),
		},
	}
	v := a.inspectToolPolicy(&ToolInspectRequest{
		Tool:      "mcp__jira__createJiraIssue",
		Args:      json.RawMessage(`{"project":"ENG","summary":"test"}`),
		Direction: "tool_call",
	})
	if v == nil {
		t.Fatal("expected non-nil verdict")
	}
	if v.Action != "block" {
		t.Errorf("expected AID Block to escalate verdict to block, got %q", v.Action)
	}
	hasAIDFinding := false
	for _, f := range v.Findings {
		if strings.HasPrefix(f, "ai-defense:") {
			hasAIDFinding = true
			break
		}
	}
	if !hasAIDFinding {
		t.Errorf("expected ai-defense-prefixed finding, got %v", v.Findings)
	}
}

// TestInspectToolPolicy_AIDLaneOffByDefaultWhenInspectorMissing
// proves the gate: an APIServer with no CiscoInspector wired returns
// the original verdict unchanged. This is the "no AID configured"
// path operators land on out of the box.
func TestInspectToolPolicy_AIDLaneOffByDefaultWhenInspectorMissing(t *testing.T) {
	a := &APIServer{
		scannerCfg:     &config.Config{},
		ciscoInspector: nil, // no AID configured
	}
	v := a.inspectToolPolicy(&ToolInspectRequest{
		Tool:      "ls",
		Args:      json.RawMessage(`{"path":"/tmp"}`),
		Direction: "tool_call",
	})
	if v == nil {
		t.Fatal("expected non-nil verdict")
	}
	if v.Action != "allow" {
		t.Errorf("expected allow without AID, got %q", v.Action)
	}
}
