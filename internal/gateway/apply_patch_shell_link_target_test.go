// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// An apply_patch envelope a connector sends as a shell command with a
// here-document names its files the way the apply_patch tool does, so a
// project link to a protected file gets the verdict of the protected name
// in every profile, and a link to an ordinary file stays allowed.
func TestShellFormApplyPatchThroughLinkGetsDirectPathVerdict(t *testing.T) {
	installSandboxMarkerRules(t)
	store, logger := testStoreAndLogger(t)
	project := t.TempDir()
	ordinary := filepath.Join(project, "notes.txt")
	if err := os.WriteFile(ordinary, []byte("notes"), 0o600); err != nil {
		t.Fatal(err)
	}
	protected, rule := sharedLocalProtectedTarget(t)
	linked := filepath.Join(project, "linked.txt")
	if err := os.Symlink(protected, linked); err != nil {
		t.Fatal(err)
	}
	ordinaryLink := filepath.Join(project, "ordinary-link.txt")
	if err := os.Symlink(ordinary, ordinaryLink); err != nil {
		t.Fatal(err)
	}
	shell := func(directives string) string {
		return "apply_patch <<\x27PATCH\x27\n*** Begin Patch\n" + directives + "*** End Patch\nPATCH\n"
	}
	forms := []struct {
		name string
		body func(path string) string
	}{
		{"Update File", func(p string) string { return shell("*** Update File: " + p + "\n@@\n-a\n+b\n") }},
		{"Add File", func(p string) string { return shell("*** Add File: " + p + "\n+b\n") }},
		{"Move to", func(p string) string {
			return shell("*** Update File: " + ordinary + "\n*** Move to: " + p + "\n@@\n-a\n+b\n")
		}},
		{"two files", func(p string) string {
			return shell("*** Update File: " + ordinary + "\n@@\n-a\n+b\n*** Add File: " + p + "\n+b\n")
		}},
	}
	for _, tier := range []string{"implicit", "default", "permissive", "strict"} {
		decide := func(t *testing.T, command string) (string, []string) {
			t.Helper()
			body := string(mustJSON(t, map[string]any{"session_id": "g831", "hook_event_name": "PreToolUse",
				"tool_name": "Bash", "cwd": project, "tool_input": map[string]any{"command": command}}))
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "codex"
			if tier != "implicit" {
				cfg.Guardrail.RulePack = tier
			}
			api := &APIServer{scannerCfg: cfg, store: store, logger: logger}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/codex/hook", strings.NewReader(body))
			req.Header.Set(hookpaths.Header, hookpaths.Resolve([]byte(body)))
			setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
			w := httptest.NewRecorder()
			api.handleAgentHook("codex").ServeHTTP(w, req)
			var answer struct {
				Action  string   `json:"action"`
				RuleIDs []string `json:"rule_ids"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &answer); err != nil || w.Code != http.StatusOK {
				t.Fatalf("status=%d err=%v body=%s", w.Code, err, w.Body.String())
			}
			return answer.Action, answer.RuleIDs
		}
		for _, form := range forms {
			t.Run(tier+"/"+form.name, func(t *testing.T) {
				wantAction, wantRules := decide(t, form.body(protected))
				if tier == "implicit" && wantAction != "block" {
					t.Fatalf("the protected name was not blocked: %v", wantRules)
				}
				gotAction, gotRules := decide(t, form.body(linked))
				if gotAction != wantAction {
					t.Fatalf("link action=%s, protected name action=%s (rules link=%v name=%v)", gotAction, wantAction, gotRules, wantRules)
				}
				if tier != "strict" && wantAction == "block" && !slices.Contains(gotRules, rule) {
					t.Fatalf("link verdict lacks %s: %v", rule, gotRules)
				}
				if action, rules := decide(t, form.body(ordinaryLink)); tier != "strict" && action != "allow" {
					t.Fatalf("link to an ordinary file: action=%s rules=%v", action, rules)
				}
			})
		}
	}
}
