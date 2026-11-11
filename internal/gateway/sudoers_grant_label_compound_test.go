// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// TestManagedSudoersGrantNamesTheGrantRuleInEveryContext: a managed gateway
// cannot read /etc/sudoers.d, so the hook cannot resolve the target of an
// apply_patch heredoc and the call also takes the conservative authorized-keys
// block. The rule that names the call follows the proven content: an
// unrestricted sudoers grant leads the rule list at the top level, inside a
// called function and inside an if block alike, not only at the top level.
// The call is blocked in every form, and a call that really writes the keys
// file keeps the keys rule first.
func TestManagedSudoersGrantNamesTheGrantRuleInEveryContext(t *testing.T) {
	if dir, err := os.Open("/etc/sudoers.d"); err == nil {
		_ = dir.Close()
		t.Skip("/etc/sudoers.d is readable here; the managed hook could resolve the target")
	}
	const grantRule = "privilege.sudoers_unrestricted_nopasswd"
	const keysRule = "persistence.ssh_authorized_keys_command"
	heredoc := func(target, line string) string {
		return "apply_patch <<\x27EOF\x27\n*** Begin Patch\n*** Add File: " + target + "\n+" + line + "\n*** End Patch\nEOF\n"
	}
	const grant = "lane ALL=(ALL) NOPASSWD: ALL"
	rows := []struct {
		name, command, first string
	}{
		{"top level", heredoc("/etc/sudoers.d/lane", grant), grantRule},
		{"called function", "f() {\n" + heredoc("/etc/sudoers.d/lane", grant) + "}\nf\n", grantRule},
		{"function then command", "f() {\n" + heredoc("/etc/sudoers.d/lane", grant) + "}\nf; true\n", grantRule},
		{"if block", "if true; then\n" + heredoc("/etc/sudoers.d/lane", grant) + "fi\n", grantRule},
		{"called function writing the keys file", "f() {\n" + heredoc("{K}", "ssh-ed25519 AAAA x") + "}\nf\n", keysRule},
		{"if block writing the keys file", "if true; then\n" + heredoc("{K}", "ssh-ed25519 AAAA x") + "fi\n", keysRule},
		{"called function writing a project file", "f() {\n" + heredoc("{P}/notes.txt", "x") + "}\nf\n", ""},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, row := range rows {
			t.Run(connector+"/"+row.name, func(t *testing.T) {
				f := newB36ManagedHookFixture(t)
				command := strings.NewReplacer("{P}", f.project, "{K}", f.keys).Replace(row.command)
				payload := mustJSON(t, map[string]any{"session_id": "gap1045", "hook_event_name": "PreToolUse", "cwd": f.project,
					"permission_mode": "default", "tool_name": "Bash", "tool_use_id": "toolu_gap1045",
					"tool_input": map[string]any{"command": command}})
				header := f.clientHeader(t, payload)
				if err := os.Chmod(f.homes, 0); err != nil {
					t.Fatal(err)
				}
				cfg := &config.Config{}
				cfg.Guardrail.Mode = "action"
				cfg.Guardrail.Connector = connector
				api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
				req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(payload)))
				req.Header.Set(hookpaths.Header, header)
				if connector == "codex" {
					setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
				}
				req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: f.home}))
				recorder := httptest.NewRecorder()
				api.handleAgentHook(connector).ServeHTTP(recorder, req)
				if err := os.Chmod(f.homes, 0o700); err != nil {
					t.Fatal(err)
				}
				var answer struct {
					Action   string   `json:"action"`
					Findings []string `json:"findings"`
				}
				if err := json.Unmarshal(recorder.Body.Bytes(), &answer); err != nil {
					t.Fatalf("answer %q: %v", recorder.Body.String(), err)
				}
				if row.first == "" {
					if answer.Action != "allow" {
						t.Fatalf("an ordinary project file: %.300s, want allow", recorder.Body.String())
					}
					return
				}
				if answer.Action != "block" {
					t.Fatalf("action %q, want block: %.300s", answer.Action, recorder.Body.String())
				}
				if len(answer.Findings) == 0 || !strings.HasPrefix(answer.Findings[0], row.first+":") {
					t.Fatalf("rules %q, want %s first", answer.Findings, row.first)
				}
			})
		}
	}
}
