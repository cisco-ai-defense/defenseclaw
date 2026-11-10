// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

func postShellApplyPatch(t *testing.T, f absolutePatchFixture, connector, profile string, managed bool, command string) (string, string) {
	t.Helper()
	installToolCallCorpusProfileConnector(t, connector, profile)
	tool, input := "Bash", map[string]any{"command": command}
	if connector == "codex" {
		tool, input = "exec_command", map[string]any{"cmd": command, "workdir": f.project}
	}
	raw := mustJSON(t, map[string]any{
		"session_id": "gap0487", "hook_event_name": "PreToolUse", "cwd": f.project,
		"permission_mode": "default", "tool_name": tool, "tool_use_id": "toolu_gap0487", "tool_input": input,
	})
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connector
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), profile)
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/"+connector+"/hook", strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(hookpaths.Header, hookpaths.Resolve(raw))
	if connector == "codex" {
		setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
	}
	if managed {
		req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: f.home}))
	}
	recorder := httptest.NewRecorder()
	api.handleAgentHook(connector).ServeHTTP(recorder, req)
	out := recorder.Body.String()
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d: %.400s", recorder.Code, out)
	}
	switch {
	case strings.Contains(out, `"action":"block"`) || strings.Contains(out, `"permissionDecision":"deny"`):
		return "block", out
	case strings.Contains(out, `"action":"alert"`):
		return "alert", out
	default:
		return "allow", out
	}
}

// Four routes (Codex and Claude Code, per-user and managed) must judge a
// shell-fed patch by the same protected paths as the native patch tool.
func TestShellHeredocApplyPatchPathRules(t *testing.T) {
	for _, connector := range []string{"codex", "claudecode"} {
		for _, managed := range []bool{false, true} {
			for _, profile := range []string{"strict", "default", "permissive"} {
				for _, row := range []struct {
					name, target, rule           string
					strict, balanced, permissive string
				}{
					// rel-1-0-6:GAP-0675: a shell call that runs apply_patch is a shell
					// command, so its startup file write is at least an alert in every
					// pack (the permissive pack used to allow it without a trace).
					{"shell profile", "{H}/.zshrc", "persistence.shell_profile_write", "block", "alert", "alert"},
					{"sudoers", "/etc/sudoers", "PATH-ETC-SUDOERS", "block", "alert", "alert"},
					{"project file", "{P}/src/main.go", "", "allow", "allow", "allow"},
				} {
					name := connector + "/" + map[bool]string{false: "per-user", true: "managed"}[managed] + "/" + profile + "/" + row.name
					t.Run(name, func(t *testing.T) {
						f := newAbsolutePatchFixture(t)
						patch := updatePatch(f.path(row.target))
						command := "apply_patch <<'PATCH'\n" + patch + "PATCH"
						got, out := postShellApplyPatch(t, f, connector, profile, managed, command)
						want := row.strict
						switch profile {
						case "default":
							want = row.balanced
						case "permissive":
							want = row.permissive
						}
						if got != want || row.rule != "" && !strings.Contains(out, row.rule) {
							t.Fatalf("decision=%s, want=%s, rule=%s: %.600s", got, want, row.rule, out)
						}
					})
				}
			}
		}
	}
}
