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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// A managed gateway cannot search a user's home under ProtectHome. The
// client's CWD evidence must place the same active hook write as a per-user
// gateway, including when the operand itself is absolute.
func TestGAP0493GitHookWriteThroughHookEntry(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway walk")
	}
	packDir := installDefaultRulePackForDataDir(t, t.TempDir())
	pack := mustLoadRulePack(t, packDir)
	for _, id := range []string{"persistence.git_hook_write", "persistence.shell_profile_write"} {
		found := false
		for _, file := range pack.RuleFiles {
			for _, rule := range file.Rules {
				found = found || rule.ID == id && rule.Severity == "MEDIUM"
			}
		}
		if !found {
			t.Fatalf("copied default pack lacks MEDIUM %s", id)
		}
	}

	homes := filepath.Join(t.TempDir(), "homes")
	home := filepath.Join(homes, "alice")
	project := filepath.Join(home, "proj")
	for _, dir := range []string{filepath.Join(project, ".git", "hooks"), filepath.Join(project, "src")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{filepath.Join(project, ".git", "HEAD"), filepath.Join(project, ".git", "hooks", "pre-commit"), filepath.Join(home, ".zshrc")} {
		if err := os.WriteFile(file, []byte("a\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Cleanup(func() { _ = os.Chmod(homes, 0o700) })

	for _, connector := range []string{"claudecode", "codex"} {
		t.Run(connector, func(t *testing.T) {
			installDefaultProfileConnector(t, connector)
			if err := ApplyConnectorRulePackOverrides(connector, pack); err != nil {
				t.Fatal(err)
			}
			for _, managed := range []bool{false, true} {
				name := "per-user"
				if managed {
					name = "managed"
				}
				t.Run(name, func(t *testing.T) {
					for _, row := range []struct {
						name, tool, command, rule string
					}{
						{"absolute redirect", "Bash", "echo x > " + filepath.Join(project, ".git", "hooks", "pre-commit"), "persistence.git_hook_write"},
						{"relative redirect", "Bash", "echo x > .git/hooks/pre-commit", "persistence.git_hook_write"},
						{"tee", "Bash", "echo x | tee .git/hooks/pre-commit", "persistence.git_hook_write"},
						{"copy", "Bash", "cp src/in .git/hooks/pre-commit", "persistence.git_hook_write"},
						{"absolute patch", "apply_patch", "*** Begin Patch\n*** Add File: " + filepath.Join(project, ".git", "hooks", "post-commit") + "\n+x\n*** End Patch\n", "persistence.git_hook_write"},
						{"shell profile control", "Bash", "echo x >> " + filepath.Join(home, ".zshrc"), "persistence.shell_profile_write"},
						{"sample control", "Bash", "echo x > .git/hooks/pre-commit.sample", ""},
						{"project control", "Bash", "echo x > src/out", ""},
					} {
						t.Run(row.name, func(t *testing.T) {
							if err := os.Chmod(homes, 0o700); err != nil {
								t.Fatal(err)
							}
							input := map[string]any{"command": row.command}
							body, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": "gap0493", "cwd": project,
								"tool_name": row.tool, "tool_input": input, "tool_use_id": t.Name()})
							if err != nil {
								t.Fatal(err)
							}
							header := hookpaths.ResolveConnector(connector, "", "PreToolUse", body)
							facts, ok := hookpaths.Decode(header)
							if !ok || facts[hookpaths.CWDKey] != project {
								t.Fatalf("client CWD evidence: %v", facts)
							}
							if managed {
								if err := os.Chmod(homes, 0); err != nil {
									t.Fatal(err)
								}
								if got := sanitizeHookCWD(project); got != "" {
									t.Fatalf("managed gateway unexpectedly resolved %q", got)
								}
							}
							cfg := &config.Config{}
							cfg.Guardrail.Mode = "action"
							cfg.Guardrail.Connector = connector
							cfg.Guardrail.RulePackDir = packDir
							api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
							req := httptest.NewRequest(http.MethodPost, "/api/v1/"+connector+"/hook", strings.NewReader(string(body)))
							req.Header.Set("Content-Type", "application/json")
							req.Header.Set(hookpaths.Header, header)
							if connector == "codex" {
								setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
							}
							if managed {
								req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
							}
							response := httptest.NewRecorder()
							api.handleAgentHook(connector).ServeHTTP(response, req)
							if err := os.Chmod(homes, 0o700); err != nil {
								t.Fatal(err)
							}
							out := response.Body.String()
							wantAction := `"action":"alert"`
							if row.rule == "" {
								wantAction = `"action":"allow"`
							}
							if response.Code != http.StatusOK || !strings.Contains(out, wantAction) {
								t.Fatalf("hook status=%d, expected %s: %.700s", response.Code, wantAction, out)
							}
							if row.rule == "" {
								if strings.Contains(out, "persistence.git_hook_write") || strings.Contains(out, "persistence.shell_profile_write") {
									t.Fatalf("ordinary write raised persistence rule: %.700s", out)
								}
							} else if !strings.Contains(out, row.rule) {
								t.Fatalf("missing %s MEDIUM alert: %.700s", row.rule, out)
							}
						})
					}
				})
			}
		})
	}
}
