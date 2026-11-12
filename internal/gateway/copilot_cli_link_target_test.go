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
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// A Copilot CLI file call (native toolCalls body or the toolName/toolArgs
// body) names its file the same way a Local call does, so a project link to a
// protected file must get the verdict the direct name gets in every profile,
// and an ordinary link must stay allowed.
func TestCopilotCLIFileCallThroughLinkGetsDirectPathVerdict(t *testing.T) {
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
	patch := func(path string) string {
		return "*** Begin Patch\n*** Update File: " + path + "\n@@\n-a\n+b\n*** End Patch\n"
	}
	type shape struct {
		name string
		args func(path string) (string, any)
	}
	shapes := []shape{
		{"apply_patch", func(p string) (string, any) { return "apply_patch", patch(p) }},
		{"apply_patch input object", func(p string) (string, any) { return "apply_patch", map[string]any{"input": patch(p)} }},
		{"edit", func(p string) (string, any) {
			return "edit", map[string]any{"path": p, "old_str": "a", "new_str": "b"}
		}},
		{"create", func(p string) (string, any) {
			return "create", map[string]any{"path": p, "file_text": "notes"}
		}},
	}
	bodies := []struct {
		name string
		make func(id, cwd, tool string, args any) map[string]any
	}{
		{"native toolCalls", func(id, cwd, tool string, args any) map[string]any {
			return map[string]any{"sessionId": id, "cwd": cwd,
				"toolCalls": []any{map[string]any{"id": id, "name": tool, "args": args}}}
		}},
		{"toolName toolArgs", func(id, cwd, tool string, args any) map[string]any {
			return map[string]any{"sessionId": id, "cwd": cwd, "toolName": tool, "toolArgs": args}
		}},
	}
	decide := func(t *testing.T, tier string, body map[string]any) (string, []string) {
		t.Helper()
		cfg := &config.Config{}
		cfg.Guardrail.Mode = "action"
		cfg.Guardrail.Connector = "copilot"
		if tier != "implicit" {
			cfg.Guardrail.RulePack = tier
		}
		api := &APIServer{scannerCfg: cfg, store: store, logger: logger}
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/copilot/hook", strings.NewReader(string(raw)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-DefenseClaw-Copilot-Event", "preToolUse")
		req.Header.Set(hookpaths.Header, hookpaths.ResolveConnector("copilot", "", "preToolUse", raw))
		w := httptest.NewRecorder()
		api.handleAgentHook("copilot").ServeHTTP(w, req)
		var answer struct {
			Action  string   `json:"action"`
			RuleIDs []string `json:"rule_ids"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &answer); err != nil || w.Code != http.StatusOK {
			t.Fatalf("status=%d err=%v body=%s", w.Code, err, w.Body.String())
		}
		return answer.Action, answer.RuleIDs
	}
	n := 0
	for _, tier := range []string{"implicit", "default", "permissive", "strict"} {
		for _, b := range bodies {
			for _, s := range shapes {
				t.Run(tier+"/"+b.name+"/"+s.name, func(t *testing.T) {
					n++
					id := "g797-" + strconv.Itoa(n)
					tool, direct := s.args(protected)
					wantAction, wantRules := decide(t, tier, b.make(id+"d", project, tool, direct))
					tool, via := s.args(linked)
					gotAction, gotRules := decide(t, tier, b.make(id+"l", project, tool, via))
					if gotAction != wantAction {
						t.Fatalf("link action=%s, direct name action=%s (rules link=%v direct=%v)", gotAction, wantAction, gotRules, wantRules)
					}
					if tier != "strict" && s.name != "view" && wantAction == "block" && !slices.Contains(gotRules, rule) {
						t.Fatalf("link verdict lacks %s: %v", rule, gotRules)
					}
					if tier == "implicit" && wantAction != "block" {
						t.Fatalf("direct protected name was not blocked: %v", wantRules)
					}
					tool, ok := s.args(ordinaryLink)
					action, rules := decide(t, tier, b.make(id+"o", project, tool, ok))
					if tier != "strict" && action != "allow" {
						t.Fatalf("ordinary link action=%s rules=%v", action, rules)
					}
				})
			}
		}
	}
}

// The same holds for the other connectors that name a file to a file tool or
// an apply_patch envelope: the link gets the verdict of the protected name
// (a read stays the alert the name gets), and an ordinary link stays allowed.
func TestFileToolThroughLinkGetsDirectPathVerdictInEveryConnector(t *testing.T) {
	installSandboxMarkerRules(t)
	store, logger := testStoreAndLogger(t)
	project := t.TempDir()
	protected, rule := sharedLocalProtectedTarget(t)
	linked := filepath.Join(project, "linked.txt")
	if err := os.Symlink(protected, linked); err != nil {
		t.Fatal(err)
	}
	ordinary := filepath.Join(project, "notes.txt")
	if err := os.WriteFile(ordinary, []byte("notes"), 0o600); err != nil {
		t.Fatal(err)
	}
	ordinaryLink := filepath.Join(project, "ordinary-link.txt")
	if err := os.Symlink(ordinary, ordinaryLink); err != nil {
		t.Fatal(err)
	}
	patch := func(path string) string {
		return "*** Begin Patch\n*** Update File: " + path + "\n@@\n-a\n+b\n*** End Patch\n"
	}
	for _, tc := range []struct {
		name, connector, tool, direct string
		input                         func(string) any
	}{
		{"codex apply_patch", "codex", "apply_patch", "block", func(p string) any { return map[string]any{"command": patch(p)} }},
		{"codex shell apply_patch Update File", "codex", "Bash", "block", func(p string) any {
			return map[string]any{"command": "apply_patch <<'PATCH'\n" + patch(p) + "PATCH\n"}
		}},
		{"codex shell apply_patch Add File", "codex", "Bash", "block", func(p string) any {
			return map[string]any{"command": "apply_patch <<'PATCH'\n*** Begin Patch\n*** Add File: " + p + "\n+b\n*** End Patch\nPATCH\n"}
		}},
		{"codex shell apply_patch Move to", "codex", "Bash", "block", func(p string) any {
			return map[string]any{"command": "apply_patch <<'PATCH'\n*** Begin Patch\n*** Update File: " + filepath.Join(project, "notes.txt") + "\n*** Move to: " + p + "\n@@\n-a\n+b\n*** End Patch\nPATCH\n"}
		}},
		{"claudecode Edit", "claudecode", "Edit", "block", func(p string) any {
			return map[string]any{"file_path": p, "old_string": "a", "new_string": "b"}
		}},
		{"claudecode Write", "claudecode", "Write", "block", func(p string) any {
			return map[string]any{"file_path": p, "content": "b"}
		}},
		{"claudecode Read", "claudecode", "Read", "alert", func(p string) any { return map[string]any{"file_path": p} }},
		{"hermes write_file", "hermes", "write_file", "block", func(p string) any {
			return map[string]any{"path": p, "content": "b"}
		}},
		{"hermes patch", "hermes", "patch", "block", func(p string) any {
			return map[string]any{"mode": "replace", "path": p, "old_string": "a", "new_string": "b"}
		}},
		{"hermes V4A patch", "hermes", "patch", "block", func(p string) any {
			return map[string]any{"mode": "patch", "patch": patch(p)}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			decide := func(path string) (string, []string) {
				event := "PreToolUse"
				if tc.connector == "hermes" {
					event = "pre_tool_call"
				}
				body := string(mustJSON(t, map[string]any{"session_id": "g797x", "hook_event_name": event,
					"tool_name": tc.tool, "cwd": project, "tool_input": tc.input(path)}))
				cfg := &config.Config{}
				cfg.Guardrail.Mode = "action"
				cfg.Guardrail.Connector = tc.connector
				api := &APIServer{scannerCfg: cfg, store: store, logger: logger}
				req := httptest.NewRequest(http.MethodPost, "/api/v1/"+tc.connector+"/hook", strings.NewReader(body))
				req.Header.Set(hookpaths.Header, hookpaths.Resolve([]byte(body)))
				if tc.connector == "codex" {
					setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
				}
				w := httptest.NewRecorder()
				api.handleAgentHook(tc.connector).ServeHTTP(w, req)
				var answer struct {
					Action  string   `json:"action"`
					RuleIDs []string `json:"rule_ids"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &answer); err != nil {
					t.Fatalf("%v %s", err, w.Body.String())
				}
				return answer.Action, answer.RuleIDs
			}
			if action, rules := decide(protected); action != tc.direct || !slices.Contains(rules, rule) {
				t.Fatalf("direct name action=%s rules=%v, want %s with %s", action, rules, tc.direct, rule)
			}
			if action, rules := decide(linked); action != tc.direct || !slices.Contains(rules, rule) {
				t.Fatalf("link action=%s rules=%v, want the direct verdict %s with %s", action, rules, tc.direct, rule)
			}
			if action, rules := decide(ordinaryLink); action != "allow" {
				t.Fatalf("ordinary link action=%s rules=%v", action, rules)
			}
		})
	}
}
