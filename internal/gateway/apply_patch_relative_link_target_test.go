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

// A relative path in an apply_patch envelope is placed in the working
// directory the hook payload carries, not the directory the hook process
// runs in. A project link named that way reaches the same protected file the
// absolute spelling does, so it gets the verdict of the protected name in
// every profile; the same relative spelling of an ordinary file or of a link
// to one stays allowed.
func TestRelativeApplyPatchThroughLinkGetsDirectPathVerdict(t *testing.T) {
	installSandboxMarkerRules(t)
	store, logger := testStoreAndLogger(t)
	project := t.TempDir()
	if err := os.MkdirAll(filepath.Join(project, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"notes.txt", "sub/deep.txt"} {
		if err := os.WriteFile(filepath.Join(project, name), []byte("notes"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	protected, rule := sharedLocalProtectedTarget(t)
	links := map[string]string{
		"linked.txt":      protected,
		"sub/linked.txt":  protected,
		"ordinary-lnk":    filepath.Join(project, "notes.txt"),
		"sub/ordinary-lk": filepath.Join(project, "notes.txt"),
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(project, name)); err != nil {
			t.Fatal(err)
		}
	}
	envelope := func(directives string) string {
		return "apply_patch <<\x27PATCH\x27\n*** Begin Patch\n" + directives + "*** End Patch\nPATCH\n"
	}
	forms := []struct {
		name string
		body func(path string) string
	}{
		{"Update File", func(p string) string { return envelope("*** Update File: " + p + "\n@@\n-a\n+b\n") }},
		{"Add File", func(p string) string { return envelope("*** Add File: " + p + "\n+b\n") }},
		{"Move to", func(p string) string {
			return envelope("*** Update File: notes.txt\n*** Move to: " + p + "\n@@\n-a\n+b\n")
		}},
		{"two files", func(p string) string {
			return envelope("*** Update File: notes.txt\n@@\n-a\n+b\n*** Add File: " + p + "\n+b\n")
		}},
	}
	spellings := func(name string) []string {
		return []string{name, "./" + name, "sub/../" + name, "./sub/./../" + name}
	}
	// The hook process runs in the package directory, never in the project.
	decide := func(t *testing.T, tier, tool, key, command string) (string, []string) {
		t.Helper()
		body := string(mustJSON(t, map[string]any{"session_id": "g831r", "hook_event_name": "PreToolUse",
			"tool_name": tool, "cwd": project, "tool_input": map[string]any{key: command}}))
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
	calls := []struct{ tool, key string }{{"Bash", "command"}, {"exec_command", "cmd"}}
	for _, tier := range []string{"implicit", "default", "permissive", "strict"} {
		for _, call := range calls {
			for _, form := range forms {
				for _, link := range []string{"linked.txt", "sub/linked.txt"} {
					for _, spelled := range spellings(link) {
						t.Run(tier+"/"+call.tool+"/"+form.name+"/"+spelled, func(t *testing.T) {
							wantAction, wantRules := decide(t, tier, call.tool, call.key, form.body(protected))
							if tier == "implicit" && wantAction != "block" {
								t.Fatalf("the protected name was not blocked: %v", wantRules)
							}
							gotAction, gotRules := decide(t, tier, call.tool, call.key, form.body(spelled))
							if gotAction != wantAction {
								t.Fatalf("relative link action=%s, protected name action=%s (rules link=%v name=%v)", gotAction, wantAction, gotRules, wantRules)
							}
							if tier != "strict" && wantAction == "block" && !slices.Contains(gotRules, rule) {
								t.Fatalf("relative link verdict lacks %s: %v", rule, gotRules)
							}
						})
					}
				}
				if tier == "strict" {
					continue
				}
				for _, ordinary := range []string{"notes.txt", "sub/deep.txt", "ordinary-lnk", "sub/ordinary-lk"} {
					t.Run(tier+"/"+call.tool+"/"+form.name+"/benign/"+ordinary, func(t *testing.T) {
						if action, rules := decide(t, tier, call.tool, call.key, form.body("./"+ordinary)); action != "allow" {
							t.Fatalf("ordinary relative path: action=%s rules=%v", action, rules)
						}
					})
				}
			}
		}
	}
}
