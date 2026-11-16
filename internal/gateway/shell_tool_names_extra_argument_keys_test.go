// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The hook table uses POSIX homes, paths and commands.

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
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// shellToolNamesHome makes a home with an inert stand-in at the SSH private
// key path (no key material) and a project directory, and points HOME at it.
func shellToolNamesHome(t *testing.T) (home, project string) {
	t.Helper()
	root := t.TempDir()
	home, project = filepath.Join(root, "home"), filepath.Join(root, "home", "proj")
	for _, dir := range []string{filepath.Join(home, ".ssh"), project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "id_rsa"), []byte("inert test fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Chdir(project)
	return home, project
}

// shellToolNamesHook sends one hook call of connectorName's hook shape
// (Amp's plugin tool.call, or a PreToolUse call) to /api/v1/<connector>/hook,
// from a managed host's peer when managed is set, else as a per-user call.
func shellToolNamesHook(t *testing.T, managed bool, mode, connectorName, tool, home, project, args string) map[string]any {
	t.Helper()
	input := json.RawMessage(args)
	var payload map[string]any
	switch connectorName {
	case "amp":
		payload = map[string]any{
			"hook_event_name": "tool.call", "session_id": "T-shell-names", "thread_id": "T-shell-names",
			"turn_id": "t1", "message_id": "t1", "tool_call_id": "tc-1", "source_event_id": "e-1",
			"source_sequence": "1", "executor_kind": "local", "cwd": project,
			"tool_name": tool, "tool_input": input, "delegation_boundary": false,
		}
	case "opencode":
		payload = map[string]any{
			"hook_event_name": "tool.execute.before", "tool_name": tool, "tool_input": input,
			"session_id": "s-shell-names", "turn_id": "m1", "tool_call_id": "c1", "agent_name": "build",
			"cwd": project, "arguments_authoritative": true, "mcp_identity_status": "not_mcp",
		}
	default:
		payload = map[string]any{
			"hook_event_name": "PreToolUse", "session_id": "s-shell-names", "turn_id": "t1",
			"cwd": project, "tool_name": tool, "tool_input": input, "tool_use_id": "u1",
		}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Guardrail.Mode = mode
	cfg.Guardrail.Connector = connectorName
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/"+connectorName+"/hook", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(hookpaths.Header, hookpaths.Resolve(body))
	if managed {
		// A managed gateway runs as its service account: its own home is
		// not the caller's, whose home comes from the kernel-verified peer.
		service := filepath.Join(filepath.Dir(home), "service")
		if err := os.MkdirAll(service, 0o700); err != nil {
			t.Fatal(err)
		}
		t.Setenv("HOME", service)
		t.Setenv("USERPROFILE", service)
		req = req.WithContext(withManagedHookPeer(withServiceAccountGateway(req.Context()),
			managedHookPeer{UID: 1001, GID: 1001, Name: "r106fxt", Home: home}))
	}
	recorder := httptest.NewRecorder()
	api.handleAgentHook(connectorName).ServeHTTP(recorder, req)
	var resp map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("hook response %q: %v", recorder.Body.String(), err)
	}
	return resp
}

// ampShellToolNames are the shell tool names an Amp call can carry: Amp's
// own (Bash, also reported as bash, shell_command, async_shell_command) and
// the generic shell execution names the trusted-action parser reads.
var ampShellToolNames = []string{
	"Bash", "bash", "shell_command", "async_shell_command", "Shell", "shell",
	"run_command", "terminal", "exec", "execute", "execute_command", "exec_command",
	"run_shell", "run_shell_command", "runshellcommand", "run_terminal_cmd", "command", "subprocess",
}

// TestShellToolNamesExtraArgumentKeysKeepTheProtectedPathRule pins
// rel-1-0-6:GAP-0201: a protected-path rule decides the same for an Amp
// shell tool call whether or not an extra argument key sits next to the
// command, for every shell tool name, per-user and from a managed peer.
// async_shell_command, run_command, terminal, exec and the other generic
// names were never judged on the command alone, so a timeout or unknown key
// next to the command turned the PATH-SSH-KEY block into an allow.
func TestShellToolNamesExtraArgumentKeysKeepTheProtectedPathRule(t *testing.T) {
	const read = `"cat ~/.ssh/id_rsa"`
	rows := []struct {
		name, args string
		rule       string // "" = any block, "allow" = must not block
	}{
		{"command", `{"command":` + read + `}`, "PATH-SSH-KEY"},
		{"cmd", `{"cmd":` + read + `}`, "PATH-SSH-KEY"},
		{"command+timeout", `{"command":` + read + `,"timeout":5}`, "PATH-SSH-KEY"},
		{"command+timeout_ms", `{"command":` + read + `,"timeout_ms":5000}`, "PATH-SSH-KEY"},
		{"command+unknown", `{"command":` + read + `,"zzz":1}`, "PATH-SSH-KEY"},
		{"cmd+unknown", `{"cmd":` + read + `,"zzz":1}`, "PATH-SSH-KEY"},
		{"command+cwd+unknown", `{"command":` + read + `,"cwd":"{PROJ}","zzz":1}`, "PATH-SSH-KEY"},
		{"command+cmd-same+unknown", `{"command":` + read + `,"cmd":` + read + `,"zzz":1}`, "PATH-SSH-KEY"},
		// Conflicting keys: two different commands block either way round.
		{"command-read+cmd-benign", `{"command":` + read + `,"cmd":"true"}`, ""},
		{"cmd-read+command-benign+unknown", `{"cmd":` + read + `,"command":"true","zzz":1}`, ""},
		// Hard negatives: benign commands with extra keys stay allowed.
		{"benign-command+timeout", `{"command":"ls -la","timeout":5}`, "allow"},
		{"benign-cmd+unknown", `{"cmd":"git status","zzz":1}`, "allow"},
		{"benign-command+cwd+unknown", `{"command":"ls","cwd":"{PROJ}","zzz":1}`, "allow"},
	}
	for _, managed := range []bool{false, true} {
		route := "per-user"
		if managed {
			route = "managed"
		}
		for _, tool := range ampShellToolNames {
			for _, row := range rows {
				t.Run(route+"/"+tool+"/"+row.name, func(t *testing.T) {
					home, project := shellToolNamesHome(t)
					args := strings.ReplaceAll(row.args, "{PROJ}", project)
					resp := shellToolNamesHook(t, managed, "action", "amp", tool, home, project, args)
					raw, _ := json.Marshal(resp)
					blocked := resp["action"] == "block"
					if row.rule == "allow" {
						if blocked {
							t.Fatalf("benign call blocked: %.800s", raw)
						}
						return
					}
					if !blocked || !strings.Contains(string(raw), row.rule) {
						t.Fatalf("want block naming %q: %.800s", row.rule, raw)
					}
				})
			}
		}
	}
	// Observe mode stays observe.
	home, project := shellToolNamesHome(t)
	resp := shellToolNamesHook(t, true, "observe", "amp", "async_shell_command", home, project, `{"command":`+read+`,"zzz":1}`)
	if resp["action"] == "block" {
		t.Fatalf("observe mode blocked: %+v", resp)
	}
}

// TestShellToolNamesExtraArgumentKeysOtherConnectors: the generic shell
// tool names reduce to the command alone on the other connectors' hook
// routes too (the same connector.ShellCommandArgs serves them all, see
// TestShellCommandArgsGenericShellToolNames), not only on Amp's. Cursor's
// shell calls arrive as beforeShellExecution or Shell, and Copilot's hook
// needs its event registration, so their routes are covered by the
// reduction table and their own shell tests.
func TestShellToolNamesExtraArgumentKeysOtherConnectors(t *testing.T) {
	const read = `"cat ~/.ssh/id_rsa"`
	for _, connectorName := range []string{"opencode", "devin", "kiro"} {
		for _, tool := range []string{"async_shell_command", "run_command", "execute"} {
			for _, row := range []struct{ name, args, rule string }{
				{"command+unknown", `{"command":` + read + `,"zzz":1}`, "PATH-SSH-KEY"},
				{"cmd+timeout", `{"cmd":` + read + `,"timeout":5}`, "PATH-SSH-KEY"},
				{"benign-command+unknown", `{"command":"ls -la","zzz":1}`, "allow"},
			} {
				t.Run(connectorName+"/"+tool+"/"+row.name, func(t *testing.T) {
					home, project := shellToolNamesHome(t)
					resp := shellToolNamesHook(t, true, "action", connectorName, tool, home, project, row.args)
					raw, _ := json.Marshal(resp)
					blocked := resp["action"] == "block"
					if row.rule == "allow" {
						if blocked {
							t.Fatalf("benign call blocked: %.800s", raw)
						}
						return
					}
					if !blocked || !strings.Contains(string(raw), row.rule) {
						t.Fatalf("want block naming %q: %.800s", row.rule, raw)
					}
				})
			}
		}
	}
}

// TestShellCommandArgsGenericShellToolNames pins the reduction itself for
// every connector: a generic shell execution name keeps its command under
// command (or cmd) whatever else the call carries, and the connector's own
// listed shell tool keeps its own key.
func TestShellCommandArgsGenericShellToolNames(t *testing.T) {
	for _, connectorName := range []string{"amp", "opencode", "hermes", "cursor", "devin", "kiro", "copilot", "antigravity", "claudecode", "codex", "openclaw", "acp"} {
		for _, tool := range []string{"async_shell_command", "run_shell_command", "run_terminal_cmd", "execute", "terminal"} {
			if connectorName == "hermes" && tool == "terminal" {
				continue // Hermes' own terminal tool: shellCommandKeys
			}
			got, ok := connector.ShellCommandArgs(connectorName, tool, json.RawMessage(`{"cmd":"ls","zzz":1,"timeout":5}`))
			if !ok || string(got) != `{"command":"ls"}` {
				t.Errorf("%s %s: %s %t; want {\"command\":\"ls\"}", connectorName, tool, got, ok)
			}
		}
		if _, ok := connector.ShellCommandArgs(connectorName, "read_file", json.RawMessage(`{"command":"ls"}`)); ok {
			t.Errorf("%s read_file reduced as a shell tool", connectorName)
		}
	}
	got, ok := connector.ShellCommandArgs("antigravity", "run_command", json.RawMessage(`{"CommandLine":"ls","zzz":1}`))
	if !ok || string(got) != `{"CommandLine":"ls"}` {
		t.Errorf("antigravity run_command: %s %t", got, ok)
	}
}

// TestShellToolNamesExtraArgumentKeysKeepTheCommandRule is the same table
// for a command rule whose decision needs a complete parse (the marker
// rule): with an extra key next to the command, only the command judged on
// its own can close the rule's proof (rel-1-0-6:GAP-0201).
func TestShellToolNamesExtraArgumentKeysKeepTheCommandRule(t *testing.T) {
	installSandboxMarkerRules(t)
	action, observe := newAmpShellToolHooks(t, "action"), newAmpShellToolHooks(t, "observe")
	const m = `"echo DCE2E-BLOCK-MARKER > /tmp/dce2e-blocked.txt"`
	for _, tool := range ampShellToolNames {
		for _, row := range []struct {
			name, args string
			rule       string // "" = any block, "allow" = must not block
		}{
			{"command", `{"command":` + m + `}`, "E2E-SANDBOX-MARKER"},
			{"cmd", `{"cmd":` + m + `}`, "E2E-SANDBOX-MARKER"},
			{"command+timeout", `{"command":` + m + `,"timeout":5}`, "E2E-SANDBOX-MARKER"},
			{"command+unknown", `{"command":` + m + `,"zzz":1}`, "E2E-SANDBOX-MARKER"},
			{"cmd+unknown", `{"cmd":` + m + `,"zzz":1}`, "E2E-SANDBOX-MARKER"},
			{"command+cmd-same+unknown", `{"command":` + m + `,"cmd":` + m + `,"zzz":1}`, "E2E-SANDBOX-MARKER"},
			{"command-marker+cmd-benign", `{"command":` + m + `,"cmd":"true"}`, ""},
			{"cmd-marker+command-benign+unknown", `{"cmd":` + m + `,"command":"true","zzz":1}`, ""},
			{"benign-command+timeout", `{"command":"ls -la","timeout":5}`, "allow"},
			{"benign-cmd+unknown", `{"cmd":"git status","zzz":1}`, "allow"},
			{"benign-marker-in-dropped-key", `{"command":"ls","note":"DCE2E-BLOCK-MARKER"}`, "allow"},
		} {
			t.Run(tool+"/"+row.name, func(t *testing.T) {
				t.Parallel()
				resp := action(t, tool+"-"+row.name, tool, row.args)
				blocked := resp.Action == "block" && resp.RawAction == "block"
				if row.rule == "allow" {
					if blocked {
						t.Fatalf("benign call blocked: reason %q", resp.Reason)
					}
					return
				}
				if !blocked || !strings.Contains(resp.Reason, row.rule) {
					t.Fatalf("action %q raw %q reason %q; want block naming %q", resp.Action, resp.RawAction, resp.Reason, row.rule)
				}
			})
		}
	}
	t.Run("observe", func(t *testing.T) {
		resp := observe(t, "observe", "async_shell_command", `{"command":`+m+`,"zzz":1}`)
		if resp.Action == "block" {
			t.Fatalf("observe mode blocked: %+v", resp)
		}
	})
}
