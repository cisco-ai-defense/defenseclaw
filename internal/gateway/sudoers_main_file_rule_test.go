// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The rows name POSIX paths (/etc/sudoers) and a POSIX managed peer.

//go:build !windows

package gateway

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

const sudoersRuleID = "PATH-ETC-SUDOERS"

// sudoersHookRow is one native tool call of a connector. body builds the
// hook payload for the project directory p; the main sudoers file is named
// by its absolute path, or relative to p where the tool takes one.
type sudoersHookRow struct {
	connector, name string
	body            func(p string) map[string]any
}

func sudoersClaudeCall(tool string, input func(p string) map[string]any) func(string) map[string]any {
	return func(p string) map[string]any {
		return map[string]any{"session_id": "gap0353", "hook_event_name": "PreToolUse", "cwd": p,
			"permission_mode": "default", "tool_name": tool, "tool_use_id": "toolu_gap0353", "tool_input": input(p)}
	}
}

func sudoersHermesCall(tool string, input func(p string) map[string]any) func(string) map[string]any {
	return func(p string) map[string]any {
		return map[string]any{"hook_event_name": "pre_tool_call", "tool_name": tool, "tool_input": input(p),
			"session_id": "20261101_1", "cwd": p, "extra": map[string]any{"tool_call_id": "call_1", "task_id": "t1"}}
	}
}

func sudoersCopilotCall(tool string, args func(p string) map[string]any) func(string) map[string]any {
	return func(p string) map[string]any {
		return map[string]any{"sessionId": "gap0353", "timestamp": 1790483549431, "cwd": p, "toolName": tool, "toolArgs": args(p)}
	}
}

func sudoersFixed(input map[string]any) func(string) map[string]any {
	return func(string) map[string]any { return input }
}

// sudoersRelative is /etc/sudoers relative to the project directory p.
func sudoersRelative(t *testing.T, p string) string {
	t.Helper()
	rel, err := filepath.Rel(p, "/etc/sudoers")
	if err != nil {
		t.Fatal(err)
	}
	return rel
}

// sudoersMainFileWrites are the writes of the main sudoers file on every
// route that reads a file-tool path or a shell write target.
func sudoersMainFileWrites(t *testing.T) []sudoersHookRow {
	const target = "/etc/sudoers"
	patch := func(path string) string {
		return "*** Begin Patch\n*** Update File: " + path + "\n@@\n Defaults env_reset\n+Defaults use_pty\n*** End Patch\n"
	}
	return []sudoersHookRow{
		{"claudecode", "Write", sudoersClaudeCall("Write", sudoersFixed(map[string]any{"file_path": target, "content": "Defaults env_reset\n"}))},
		{"claudecode", "Write dot segment", sudoersClaudeCall("Write", sudoersFixed(map[string]any{"file_path": "/etc/./sudoers", "content": "Defaults env_reset\n"}))},
		{"claudecode", "Write double slash", sudoersClaudeCall("Write", sudoersFixed(map[string]any{"file_path": "/etc//sudoers", "content": "Defaults env_reset\n"}))},
		// The owner reads the path case-folded and the macOS /private/etc real
		// path as /etc (rel-1-0-6:GAP-0398).
		{"claudecode", "Write upper case", sudoersClaudeCall("Write", sudoersFixed(map[string]any{"file_path": "/ETC/SUDOERS", "content": "Defaults env_reset\n"}))},
		{"claudecode", "Write macOS real path", sudoersClaudeCall("Write", sudoersFixed(map[string]any{"file_path": "/private/etc/sudoers", "content": "Defaults env_reset\n"}))},
		{"claudecode", "Bash redirect mixed case", sudoersClaudeCall("Bash", sudoersFixed(map[string]any{"command": "echo Defaults use_pty >> /Etc/Sudoers"}))},
		{"hermes", "write_file macOS real path", sudoersHermesCall("write_file", sudoersFixed(map[string]any{"path": "/private/etc/sudoers", "content": "Defaults env_reset\n"}))},
		{"claudecode", "Edit", sudoersClaudeCall("Edit", sudoersFixed(map[string]any{"file_path": target, "old_string": "Defaults env_reset", "new_string": "Defaults !env_reset"}))},
		{"claudecode", "MultiEdit", sudoersClaudeCall("MultiEdit", sudoersFixed(map[string]any{"file_path": target,
			"edits": []any{map[string]any{"old_string": "Defaults env_reset", "new_string": "Defaults !env_reset"}}}))},
		{"claudecode", "Bash redirect", sudoersClaudeCall("Bash", sudoersFixed(map[string]any{"command": "echo Defaults use_pty > /etc/sudoers"}))},
		{"claudecode", "Bash append redirect", sudoersClaudeCall("Bash", sudoersFixed(map[string]any{"command": "echo Defaults use_pty >> /etc/sudoers"}))},
		{"claudecode", "Bash tee -a", sudoersClaudeCall("Bash", sudoersFixed(map[string]any{"command": "echo Defaults use_pty | tee -a /etc/sudoers"}))},
		{"claudecode", "Bash sudo tee", sudoersClaudeCall("Bash", sudoersFixed(map[string]any{"command": "echo Defaults use_pty | sudo tee /etc/sudoers"}))},
		{"codex", "Bash redirect", sudoersClaudeCall("Bash", sudoersFixed(map[string]any{"command": "echo Defaults use_pty >> /etc/sudoers"}))},
		{"codex", "apply_patch relative", sudoersClaudeCall("apply_patch", func(p string) map[string]any {
			return map[string]any{"command": patch(sudoersRelative(t, p))}
		})},
		{"hermes", "write_file", sudoersHermesCall("write_file", sudoersFixed(map[string]any{"path": target, "content": "Defaults env_reset\n"}))},
		{"hermes", "patch replace", sudoersHermesCall("patch", sudoersFixed(map[string]any{"path": target, "old_string": "Defaults env_reset", "new_string": "Defaults !env_reset"}))},
		{"hermes", "patch replace mode", sudoersHermesCall("patch", sudoersFixed(map[string]any{"mode": "replace", "path": target, "old_string": "Defaults env_reset", "new_string": "Defaults !env_reset"}))},
		{"hermes", "patch V4A", sudoersHermesCall("patch", sudoersFixed(map[string]any{"mode": "patch", "patch": patch(target)}))},
		{"hermes", "terminal", sudoersHermesCall("terminal", sudoersFixed(map[string]any{"command": "echo Defaults use_pty >> /etc/sudoers"}))},
		{"copilot", "create", sudoersCopilotCall("create", sudoersFixed(map[string]any{"path": target, "file_text": "Defaults env_reset\n"}))},
		{"copilot", "edit", sudoersCopilotCall("edit", sudoersFixed(map[string]any{"path": target, "old_str": "Defaults env_reset", "new_str": "Defaults !env_reset"}))},
		{"copilot", "bash", sudoersCopilotCall("bash", sudoersFixed(map[string]any{"command": "echo Defaults use_pty >> /etc/sudoers"}))},
	}
}

// sudoersBenignNeighbours read the main file, check it with visudo, or
// write project files that only share its name.
func sudoersBenignNeighbours() []sudoersHookRow {
	in := func(name string) func(p string) string {
		return func(p string) string { return filepath.Join(p, name) }
	}
	write := func(path func(string) string) func(string) map[string]any {
		return func(p string) map[string]any {
			return map[string]any{"file_path": path(p), "content": "Defaults env_reset\n"}
		}
	}
	return []sudoersHookRow{
		{"claudecode", "Read", sudoersClaudeCall("Read", sudoersFixed(map[string]any{"file_path": "/etc/sudoers"}))},
		{"claudecode", "Bash cat", sudoersClaudeCall("Bash", sudoersFixed(map[string]any{"command": "cat /etc/sudoers"}))},
		{"claudecode", "Read macOS real path", sudoersClaudeCall("Read", sudoersFixed(map[string]any{"file_path": "/private/etc/sudoers"}))},
		{"claudecode", "Write project SUDOERS", sudoersClaudeCall("Write", write(in("SUDOERS")))},
		{"claudecode", "Write project private/etc/sudoers", sudoersClaudeCall("Write", write(in("private/etc/sudoers")))},
		{"claudecode", "Bash visudo -c", sudoersClaudeCall("Bash", sudoersFixed(map[string]any{"command": "visudo -c"}))},
		{"claudecode", "Bash sudo visudo -c -f", sudoersClaudeCall("Bash", sudoersFixed(map[string]any{"command": "sudo visudo -c -f /etc/sudoers"}))},
		{"claudecode", "Bash grep", sudoersClaudeCall("Bash", sudoersFixed(map[string]any{"command": "grep -n Defaults /etc/sudoers"}))},
		{"claudecode", "Write project sudoers", sudoersClaudeCall("Write", write(in("sudoers")))},
		{"claudecode", "Write project sudoers.example", sudoersClaudeCall("Write", write(in("sudoers.example")))},
		{"claudecode", "Write project etc/sudoers", sudoersClaudeCall("Write", write(in("etc/sudoers")))},
		{"claudecode", "Bash redirect project sudoers", sudoersClaudeCall("Bash", func(p string) map[string]any {
			return map[string]any{"command": "echo Defaults use_pty > " + filepath.Join(p, "sudoers.bak")}
		})},
		{"codex", "apply_patch project sudoers", sudoersClaudeCall("apply_patch", sudoersFixed(map[string]any{
			"command": "*** Begin Patch\n*** Add File: sudoers\n+Defaults use_pty\n*** End Patch\n"}))},
		{"hermes", "read_file", sudoersHermesCall("read_file", sudoersFixed(map[string]any{"path": "/etc/sudoers"}))},
		{"hermes", "write_file project sudoers", sudoersHermesCall("write_file", func(p string) map[string]any {
			return map[string]any{"path": filepath.Join(p, "sudoers"), "content": "Defaults env_reset\n"}
		})},
		{"hermes", "patch project sudoers.example", sudoersHermesCall("patch", func(p string) map[string]any {
			return map[string]any{"path": filepath.Join(p, "sudoers.example"), "old_string": "a", "new_string": "b"}
		})},
		{"copilot", "view", sudoersCopilotCall("view", sudoersFixed(map[string]any{"path": "/etc/sudoers"}))},
		{"copilot", "create project sudoers", sudoersCopilotCall("create", func(p string) map[string]any {
			return map[string]any{"path": filepath.Join(p, "sudoers"), "file_text": "Defaults env_reset\n"}
		})},
	}
}

// postSudoersHook posts the row to its connector hook in action mode on the
// profile pack, as the per-user gateway or, with managed, as a managed
// gateway that knows the caller. It returns whether the call was refused,
// whether the response names the sudoers rule, and the response.
func postSudoersHook(t *testing.T, row sudoersHookRow, profile string, managed bool) (bool, bool, string) {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "home")
	project := filepath.Join(home, "proj")
	if err := os.MkdirAll(filepath.Join(project, "private", "etc"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(project, "etc"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"sudoers", "sudoers.example", "etc/sudoers", "SUDOERS", "private/etc/sudoers"} {
		if err := os.WriteFile(filepath.Join(project, name), []byte("a\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	installToolCallCorpusProfileConnector(t, row.connector, profile)
	raw := string(mustJSON(t, row.body(project)))
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = row.connector
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), profile)
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/"+row.connector+"/hook", strings.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	switch row.connector {
	case "copilot":
		req.Header.Set("X-DefenseClaw-Copilot-Event", "preToolUse")
		req.Header.Set(hookpaths.Header, hookpaths.ResolveConnector("copilot", "", "preToolUse", []byte(raw)))
	case "codex":
		req.Header.Set(hookpaths.Header, hookpaths.Resolve([]byte(raw)))
		setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
	default:
		req.Header.Set(hookpaths.Header, hookpaths.Resolve([]byte(raw)))
	}
	if managed {
		req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
	}
	recorder := httptest.NewRecorder()
	api.handleAgentHook(row.connector).ServeHTTP(recorder, req)
	body := recorder.Body.String()
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d: %.400s", recorder.Code, body)
	}
	blocked := strings.Contains(body, `"action":"block"`) || strings.Contains(body, `"permissionDecision":"deny"`)
	return blocked, strings.Contains(body, sudoersRuleID), body
}

// TestSudoersRuleCoversTheMainFile: PATH-ETC-SUDOERS fires for a write,
// append or edit of /etc/sudoers itself on every file-tool and shell route
// of Claude Code, Codex, Hermes and the Copilot CLI, per-user and managed
// (rel-1-0-6:GAP-0353). Its severity is unchanged (HIGH), so the profile
// decides as for any HIGH finding: strict refuses the call, default and
// permissive (block at CRITICAL) report it as an alert.
func TestSudoersRuleCoversTheMainFile(t *testing.T) {
	for _, profile := range []string{"default", "permissive", "strict"} {
		for _, managed := range []bool{false, true} {
			for _, row := range sudoersMainFileWrites(t) {
				name := profile + "/" + map[bool]string{false: "per-user", true: "managed"}[managed] + "/" + row.connector + " " + row.name
				t.Run(name, func(t *testing.T) {
					blocked, named, body := postSudoersHook(t, row, profile, managed)
					if !named {
						t.Fatalf("the write of /etc/sudoers does not name %s: %.600s", sudoersRuleID, body)
					}
					if want := profile == "strict"; blocked != want {
						t.Fatalf("blocked = %t, want %t (HIGH on the %s pack): %.600s", blocked, want, profile, body)
					}
				})
			}
		}
	}
}

// TestSudoersRuleLeavesItsNeighboursAlone: reading the main file, visudo
// checks and project files that only share its name stay allowed with no
// sudoers finding, in every profile, per-user and managed.
func TestSudoersRuleLeavesItsNeighboursAlone(t *testing.T) {
	for _, profile := range []string{"default", "permissive", "strict"} {
		for _, managed := range []bool{false, true} {
			for _, row := range sudoersBenignNeighbours() {
				name := profile + "/" + map[bool]string{false: "per-user", true: "managed"}[managed] + "/" + row.connector + " " + row.name
				t.Run(name, func(t *testing.T) {
					blocked, named, body := postSudoersHook(t, row, profile, managed)
					if blocked || named {
						t.Fatalf("blocked = %t, names %s = %t, want neither: %.600s", blocked, sudoersRuleID, named, body)
					}
				})
			}
		}
	}
}

// TestSudoersRuleLeavesSecureClientUnchanged: a Secure Client gateway
// judges hook calls with Cisco AI Defense only, never the rule packs, so a
// write of /etc/sudoers there gets the same answer as before this rule
// covered the main file and never names it.
func TestSudoersRuleLeavesSecureClientUnchanged(t *testing.T) {
	for _, row := range sudoersMainFileWrites(t) {
		t.Run(row.connector+" "+row.name, func(t *testing.T) {
			project := t.TempDir()
			raw := string(mustJSON(t, row.body(project)))
			cfg := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
			cfg.Enterprise.Profile = managed.ProfileSecureClient
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = row.connector
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/"+row.connector+"/hook", strings.NewReader(raw))
			req.Header.Set("Content-Type", "application/json")
			if row.connector == "copilot" {
				req.Header.Set("X-DefenseClaw-Copilot-Event", "preToolUse")
			}
			if row.connector == "codex" {
				setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
			}
			recorder := httptest.NewRecorder()
			api.handleAgentHook(row.connector).ServeHTTP(recorder, req)
			if body := recorder.Body.String(); strings.Contains(body, sudoersRuleID) {
				t.Fatalf("a Secure Client hook answer names %s: %.600s", sudoersRuleID, body)
			}
		})
	}
}
