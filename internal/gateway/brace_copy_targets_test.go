// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// TestBraceBackupCopyInProjectIsAllowed: a cp operand spelled as a brace
// expansion of plain text is the fixed words bash makes of it. A backup copy
// of a project file to a brace-expanded name in the project writes only that
// project file, so action mode allows it per-user as on managed, for Claude
// Code and Codex (rel-1-0-6 GAP-0202). A brace copy whose real destination
// is the keys file, or the project link to it, keeps blocking on both.
func TestBraceBackupCopyInProjectIsAllowed(t *testing.T) {
	r106Reader2Check(t, []r106Reader2Row{
		{"three operands, brace backup", "project", `cp README.md README.md{,.bak}`, "allow"},
		{"three operands, other suffix", "project", `cp a.txt a.txt{,.orig}`, "allow"},
		{"backup idiom", "project", `cp README.md{,.bak}`, "allow"},
		{"backup idiom then read", "project", `cp a.txt{,.orig} && cat a.txt.orig`, "allow"},
		{"two sources into a project dir", "project", `cp {a.txt,README.md} ordinary/`, "allow"},
		{"absolute backup", "project", `cp {P}/a.txt {P}/a.txt{,.orig}`, "allow"},
		{"many sources into a project dir", "project", `cp a.txt{1..300} ordinary/`, "allow"},
		{"keys file by brace", "project", `cp {README.md,{K}}`, "block"},
		{"keys file by relative brace", "project", `cp {README.md,../.ssh/authorized_keys}`, "block"},
	})
}

// TestBraceCopyOntoKeysLinkBlocks: a brace copy whose real destination is
// the project link to the keys file writes the keys file; a managed gateway
// blocks it from the hook client reading of the expanded destination, as a
// per-user gateway does (rel-1-0-6 GAP-0205). A copy past the brace budget
// takes the evaluation limit on both before any reader expands it
// (GAP-0187); it proves no target, so it alerts outside strict and blocks in
// the strict pack (rel-1-0-6 GAP-0675 round 10).
func TestBraceCopyOntoKeysLinkBlocks(t *testing.T) {
	r106Reader2Check(t, []r106Reader2Row{
		{"link by brace", "project", `cp {README.md,keylink}`, "block"},
		{"link by backup idiom", "project", `echo x > key && cp key{,link}`, "block"},
		{"link by absolute brace", "project", `cp {P}/{README.md,keylink}`, "block"},
	})
	// The limit alone, no proven target: an alert outside strict, in the
	// per-user and the managed cell alike, never a silent allow, and a block
	// in the strict pack.
	for _, connector := range []string{"claudecode", "codex"} {
		f := newB36ManagedHookFixture(t)
		payload := mustJSON(t, map[string]any{"session_id": "r106", "hook_event_name": "PreToolUse", "cwd": f.project,
			"permission_mode": "default", "tool_name": "Bash", "tool_use_id": "toolu_r106",
			"tool_input": map[string]any{"command": `cp a.txt{1..70000} ordinary/`, "description": "Run test fixture command"}})
		header := f.clientHeader(t, payload)

		cfg := &config.Config{}
		cfg.Guardrail.Mode = "action"
		cfg.Guardrail.Connector = connector
		api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(payload)))
		req.Header.Set(hookpaths.Header, header)
		if connector == "codex" {
			setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
		}
		recorder := httptest.NewRecorder()
		api.handleAgentHook(connector).ServeHTTP(recorder, req)
		var answer agentHookResponse
		if err := json.Unmarshal(recorder.Body.Bytes(), &answer); err != nil {
			t.Fatalf("%s per-user answer %q: %v", connector, recorder.Body.String(), err)
		}
		if answer.Action != "alert" {
			t.Errorf("%s past the brace budget: per-user action %q, want alert", connector, answer.Action)
		}
		if !slices.Contains(answer.Findings, evaluationLimitRuleID) && !strings.Contains(recorder.Body.String(), evaluationLimitRuleID) {
			t.Errorf("%s past the brace budget: per-user answer names no %s: %s", connector, evaluationLimitRuleID, recorder.Body.String())
		}
		if strings.TrimSpace(answer.Reason) == "" && strings.TrimSpace(answer.AdditionalContext) == "" && len(answer.HookOutput) == 0 {
			t.Errorf("%s past the brace budget: per-user alert carries no warning: %s", connector, recorder.Body.String())
		}
		if got := f.post(t, connector, payload, header); got != "alert" {
			t.Errorf("%s past the brace budget: managed %s, want alert", connector, got)
		}
		if err := os.Chmod(f.homes, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, connector := range []string{"claudecode", "codex"} {
		f := newB36ManagedHookFixture(t).strict(t)
		payload := mustJSON(t, map[string]any{"session_id": "r106", "hook_event_name": "PreToolUse", "cwd": f.project,
			"permission_mode": "default", "tool_name": "Bash", "tool_use_id": "toolu_r106",
			"tool_input": map[string]any{"command": `cp a.txt{1..70000} ordinary/`, "description": "Run test fixture command"}})
		if got := f.post(t, connector, payload, f.clientHeader(t, payload)); got != "block" {
			t.Errorf("%s past the brace budget, strict pack: managed %s, want block", connector, got)
		}
	}
}
