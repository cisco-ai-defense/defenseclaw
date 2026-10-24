// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// renderPerUserShellHooksAt renders tc's per-user hooks into data/hooks in
// failMode against the gateway at addr and returns the hook directory.
func renderPerUserShellHooksAt(t *testing.T, tc installInFlightShellCase, data, failMode, addr string) string {
	t.Helper()
	hooks := filepath.Join(data, "hooks")
	if tc.conn.Name() == "cursor" {
		// Cursor's connector setup renders its action hook closed in every
		// mode; the open render is the one an observe install runs.
		if err := writeHookScriptsCommonWithFailMode(hooks, addr, "test-token", failMode, []string{"cursor-hook.sh"}); err != nil {
			t.Fatal(err)
		}
		return hooks
	}
	opts := SetupOpts{DataDir: data, APIAddr: addr, APIToken: "test-token", HookFailMode: failMode, GuardrailMode: "action", WorkspaceDir: data}
	if err := WriteHookScriptsForConnectorObjectWithOpts(hooks, opts, tc.conn); err != nil {
		t.Fatal(err)
	}
	return hooks
}

// runShellHookWith runs the hook at path with the case's arguments, env on
// top of the sanitized test environment, and stdin.
func runShellHookWith(t *testing.T, path string, args, env []string, stdin string) (int, string, string) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{path}, args...)...)
	cmd.Env = append(append(sanitizedTestEnv(), "DEFENSECLAW_HOOK_MAX_BODY=4096"), env...)
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("run %s: %v", path, err)
		}
		code = exitErr.ExitCode()
	}
	return code, stdout.String(), stderr.String()
}

// GAP-0948: a per-user shell hook looked for the install lock only in the
// data directory DEFENSECLAW_HOME named, else ~/.defenseclaw. The gateway
// renders the hook into its resolved data directory (data_dir/hooks), and an
// agent may run it without DEFENSECLAW_HOME, or data_dir may differ from
// DEFENSECLAW_HOME. The hook then checked a data directory no installer held
// and, in fail mode open, let the call run while the installer held the one
// the hook was installed in. Every per-user shell hook now also reads the
// lock of the folder above its own hooks folder, on every path: a missing
// home, a call that reaches no gateway and a bootstrap failure.
func TestPerUserShellHookFindsTheInstallLockOfItsOwnDataDirectory(t *testing.T) {
	layouts := []struct {
		name string
		// homeData: ~/.defenseclaw exists, a data directory the hook was not
		// installed in.
		homeData bool
		// customHome: DEFENSECLAW_HOME names a data directory other than the
		// hook's (data_dir set apart from DEFENSECLAW_HOME).
		customHome bool
		// lockInCustomHome: the installer holds DEFENSECLAW_HOME, not the
		// hook's data directory.
		lockInCustomHome bool
		// broken: the hook fails before its helpers load.
		broken bool
	}{
		{name: "no DEFENSECLAW_HOME and no ~/.defenseclaw"},
		{name: "no DEFENSECLAW_HOME and another ~/.defenseclaw", homeData: true},
		{name: "DEFENSECLAW_HOME names another data directory", customHome: true},
		{name: "the installer holds DEFENSECLAW_HOME, not the hook's data directory", customHome: true, lockInCustomHome: true},
		{name: "no DEFENSECLAW_HOME and a missing hardening helper", broken: true},
		{name: "another ~/.defenseclaw and a missing hardening helper", homeData: true, broken: true},
	}
	for _, tc := range installInFlightShellCases(t) {
		// The inspect hooks serve every connector and close in every mode,
		// and so does any non-zero exit of Cursor's: no open control.
		closedAnyway := tc.invoke.script == "cursor-hook.sh" || strings.HasPrefix(tc.invoke.script, "inspect-")
		// A per-user hook rendered closed for an open config (sa-port-peer:
		// per-user hooks fail closed in every mode) has no open control
		// either; it returns when an OSS open render does.
		if !closedAnyway {
			rendered, err := os.ReadFile(filepath.Join(renderPerUserShellHooks(t, tc, t.TempDir(), "open"), tc.invoke.script))
			if err != nil {
				t.Fatal(err)
			}
			closedAnyway = !strings.Contains(string(rendered), `FAIL_MODE="open"`)
		}
		for _, layout := range layouts {
			t.Run(tc.name+"/"+tc.invoke.script+"/"+layout.name, func(t *testing.T) {
				t.Parallel()
				answer := func(install bool) (bool, string) {
					data := filepath.Join(t.TempDir(), "custom-data")
					home := t.TempDir()
					env := []string{"HOME=" + home}
					lockDir := data
					if layout.homeData {
						if err := os.Mkdir(filepath.Join(home, ".defenseclaw"), 0o700); err != nil {
							t.Fatal(err)
						}
					}
					if layout.customHome {
						other := t.TempDir()
						env = append(env, "DEFENSECLAW_HOME="+other)
						if layout.lockInCustomHome {
							lockDir = other
						}
					}
					hooks := renderPerUserShellHooks(t, tc, data, "open")
					if layout.broken {
						if err := os.Remove(filepath.Join(hooks, "_hardening.sh")); err != nil {
							t.Fatal(err)
						}
					}
					if install {
						if err := os.Mkdir(filepath.Join(lockDir, ".install.lock"), 0o700); err != nil {
							t.Fatal(err)
						}
					}
					code, stdout, stderr := runShellHookWith(t, filepath.Join(hooks, tc.invoke.script), tc.invoke.args, append(env, tc.invoke.env...), tc.invoke.stdin)
					return shellHookBlocksNatively(tc.invoke.script, code, stdout),
						fmt.Sprintf("exit %d stdout %q stderr %q", code, stdout, stderr)
				}
				if blocks, got := answer(true); !blocks {
					t.Fatalf("fail mode open while the installer holds the data directory: %s, want a block", got)
				}
				if !closedAnyway {
					if blocks, got := answer(false); blocks {
						t.Fatalf("fail mode open without an install: %s, want the call to run", got)
					}
				}
			})
		}
	}
}

// codexControlledEvents are the Codex events whose answer can stop what the
// event announces (codexEventCanControl for codex-hooks-v4), less Stop and
// SubagentStop, which a failure answers with the neutral stop rule (#1140).
var codexControlledEvents = []string{"SessionStart", "UserPromptSubmit", "PreToolUse", "PermissionRequest", "PostToolUse", "PreCompact", "PostCompact"}

// codexEventPayload is a Codex hook input for event.
func codexEventPayload(event string) string {
	return `{"hook_event_name":"` + event + `","session_id":"s1","turn_id":"t1","prompt":"hello","tool_name":"Bash","tool_input":{"command":"echo hi"}}`
}

// GAP-0949 and its class: the per-user Codex shell hook blocked with exit 2,
// before its helpers loaded and in every failure after. Codex v0.130+ reads
// a non-zero UserPromptSubmit status as a hook failure and submits the
// prompt, so during an install (and in fail mode closed) a prompt ran.
// Every block of the per-user Codex hook is now Codex's own block for the
// registered event, on stdout with exit 0, as the native hook answers
// (emitCodexBlock): a bootstrap failure, a disabled home, an unreachable or
// failing gateway, an answer without a verdict, and a gateway block without
// codex_output.
func TestCodexShellHookBlocksEveryEventItCanBlockInCodexsShape(t *testing.T) {
	codex := installInFlightShellCase{"codex", NewCodexConnector(), hookArgvCase{script: "codex-hook.sh"}}
	failures := []struct {
		name string
		// answer is the gateway's answer; nil leaves the port refused.
		answer func(w http.ResponseWriter)
		// breaks changes the rendered state before the call.
		breaks func(t *testing.T, data, hooks string)
	}{
		{name: "the hardening helper is missing", breaks: func(t *testing.T, _, hooks string) {
			if err := os.Remove(filepath.Join(hooks, "_hardening.sh")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "the hardening helper fails", breaks: func(t *testing.T, _, hooks string) {
			if err := os.WriteFile(filepath.Join(hooks, "_hardening.sh"), []byte("return 3\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "the hook home is disabled", breaks: func(t *testing.T, data, _ string) {
			if err := os.WriteFile(filepath.Join(data, ".disabled"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "the gateway is unreachable"},
		{name: "the gateway answers HTTP 503", answer: func(w http.ResponseWriter) { w.WriteHeader(http.StatusServiceUnavailable) }},
		{name: "the gateway answers no verdict", answer: func(w http.ResponseWriter) { _, _ = w.Write([]byte(`{"action":"maybe"}`)) }},
		{name: "the gateway blocks without codex_output", answer: func(w http.ResponseWriter) {
			_, _ = w.Write([]byte(`{"action":"block","reason":"policy says no"}`))
		}},
	}
	modes := []struct {
		name     string
		failMode string
		install  bool
	}{
		{"fail mode open during an install", "open", true},
		{"fail mode closed", "closed", false},
	}
	for _, event := range codexControlledEvents {
		for _, failure := range failures {
			for _, mode := range modes {
				t.Run(event+"/"+failure.name+"/"+mode.name, func(t *testing.T) {
					t.Parallel()
					data := t.TempDir()
					addr := freeAPIAddr(t)
					if failure.answer != nil {
						server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { failure.answer(w) }))
						t.Cleanup(server.Close)
						addr = strings.TrimPrefix(server.URL, "http://")
					}
					hooks := renderPerUserShellHooksAt(t, codex, data, mode.failMode, addr)
					if failure.breaks != nil {
						failure.breaks(t, data, hooks)
					}
					if mode.install {
						if err := os.Mkdir(filepath.Join(data, ".install.lock"), 0o700); err != nil {
							t.Fatal(err)
						}
					}
					args := codexBoundShellHookArgsForTest(t, "codex-hook.sh", event)[1:]
					code, stdout, stderr := runShellHookWith(t, filepath.Join(hooks, "codex-hook.sh"), args,
						[]string{"HOME=" + data, "DEFENSECLAW_HOME=" + data}, codexEventPayload(event))
					if !codexBlockAnswer(event, code, stdout) {
						t.Fatalf("exit %d stdout %q stderr %q, want Codex's own %s block on stdout with exit 0", code, stdout, stderr, event)
					}
				})
			}
		}
	}
}

// claudeBlockAnswer reports an answer Claude Code reads as a block of event:
// exit 2, or exit 0 with one event-shaped deny or block.
func claudeBlockAnswer(event string, code int, stdout string) bool {
	if code == 2 {
		return true
	}
	if code != 0 {
		return false
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 1 {
		return false
	}
	var answer map[string]any
	if json.Unmarshal([]byte(lines[0]), &answer) != nil {
		return false
	}
	nested, _ := answer["hookSpecificOutput"].(map[string]any)
	switch event {
	case "PreToolUse":
		return nested["permissionDecision"] == "deny"
	case "PermissionRequest":
		decision, _ := nested["decision"].(map[string]any)
		return decision["behavior"] == "deny"
	}
	return answer["decision"] == "block"
}

// GAP-0950 and its class: the Claude Code and Codex shell hooks printed the
// gateway's native object before they read its action, so a 2xx answer
// with action block (or confirm) and an object that allows reached the
// agent as the allow, in every fail mode and while an install held the data
// directory. The Devin hook printed such an object as its rejection text.
// Each hook now answers exactly one decision, the block: an object that
// does not deny (or ask) for the call's event is refused closed, as the
// native hook refuses it (nativeOutputAgrees). An object that agrees is
// still forwarded as it is.
func TestShellHooksAnswerOneDecisionWhenTheGatewayBlocks(t *testing.T) {
	claude := installInFlightShellCase{"claudecode", NewClaudeCodeConnector(), hookArgvCase{script: "claude-code-hook.sh"}}
	codex := installInFlightShellCase{"codex", NewCodexConnector(), hookArgvCase{script: "codex-hook.sh"}}
	devin := installInFlightShellCase{"devin", NewDevinConnector(), hookArgvCase{script: "devin-hook.sh"}}
	rows := []struct {
		name   string
		tc     installInFlightShellCase
		event  string
		action string
		output string
	}{
		{"claude PreToolUse allow", claude, "PreToolUse", "block", `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}`},
		{"claude PreToolUse deny for another event", claude, "PreToolUse", "block", `{"hookSpecificOutput":{"hookEventName":"PostToolUse","permissionDecision":"deny"}}`},
		{"claude PermissionRequest allow", claude, "PermissionRequest", "block", `{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow"}}}`},
		{"claude UserPromptSubmit context only", claude, "UserPromptSubmit", "block", `{"hookSpecificOutput":{"hookEventName":"UserPromptSubmit","additionalContext":"go ahead"}}`},
		{"claude UserPromptSubmit approve", claude, "UserPromptSubmit", "block", `{"decision":"approve"}`},
		{"claude PreToolUse confirm with allow", claude, "PreToolUse", "confirm", `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}`},
		{"codex PreToolUse allow", codex, "PreToolUse", "block", `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}`},
		{"codex PermissionRequest allow", codex, "PermissionRequest", "block", `{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow"}}}`},
		{"codex UserPromptSubmit context only", codex, "UserPromptSubmit", "block", `{"hookSpecificOutput":{"hookEventName":"UserPromptSubmit","additionalContext":"go ahead"}}`},
		{"codex SessionStart continue", codex, "SessionStart", "block", `{"continue":true}`},
		{"codex PostToolUse empty", codex, "PostToolUse", "block", `{}`},
		{"codex PreToolUse confirm with allow", codex, "PreToolUse", "confirm", `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}`},
		{"devin PreToolUse allow", devin, "PreToolUse", "block", `{"decision":"allow"}`},
	}
	modes := []struct {
		name     string
		failMode string
		install  bool
	}{
		{"fail mode open", "open", false},
		{"fail mode open, an install starts during the call", "open", true},
		{"fail mode closed", "closed", false},
	}
	for _, row := range rows {
		for _, mode := range modes {
			t.Run(row.name+"/"+mode.name, func(t *testing.T) {
				t.Parallel()
				data := t.TempDir()
				body := `{"action":"` + row.action + `","reason":"policy says no","claude_code_output":` + row.output +
					`,"codex_output":` + row.output + `,"hook_output":` + row.output + `}`
				var once sync.Once
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					if mode.install {
						once.Do(func() {
							if err := os.Mkdir(filepath.Join(data, ".install.lock"), 0o700); err != nil {
								t.Error(err)
							}
						})
					}
					_, _ = w.Write([]byte(body))
				}))
				t.Cleanup(server.Close)
				hooks := renderPerUserShellHooksAt(t, row.tc, data, mode.failMode, strings.TrimPrefix(server.URL, "http://"))
				// Per-user hooks post through the native gateway's connected-peer
				// proof (sa-port-peer): without it no call reaches the stub.
				installNativeGatewayForHookTest(t, data)
				var args []string
				payload := `{"hook_event_name":"` + row.event + `","session_id":"s1","cwd":"/work/proj","prompt":"hello","tool_name":"Bash","tool_input":{"command":"echo hi"}}`
				if row.tc.conn.Name() == "codex" {
					args = codexBoundShellHookArgsForTest(t, "codex-hook.sh", row.event)[1:]
				}
				code, stdout, stderr := runShellHookWith(t, filepath.Join(hooks, row.tc.invoke.script), args,
					[]string{"HOME=" + data, "DEFENSECLAW_HOME=" + data}, payload)
				got := fmt.Sprintf("exit %d stdout %q stderr %q", code, stdout, stderr)
				if strings.Contains(stdout, row.output) {
					t.Fatalf("%s: the hook forwarded the gateway's contradicting object beside its %s", got, row.action)
				}
				var blocks bool
				switch row.tc.conn.Name() {
				case "claudecode":
					blocks = claudeBlockAnswer(row.event, code, stdout)
				case "codex":
					blocks = codexBlockAnswer(row.event, code, stdout)
				default:
					blocks = code == 2
				}
				if !blocks {
					t.Fatalf("%s, want one block of the %s", got, row.event)
				}
			})
		}
	}
}

// An object that agrees with the gateway's action is forwarded as it is.
func TestShellHooksForwardANativeObjectThatAgrees(t *testing.T) {
	claude := installInFlightShellCase{"claudecode", NewClaudeCodeConnector(), hookArgvCase{script: "claude-code-hook.sh"}}
	codex := installInFlightShellCase{"codex", NewCodexConnector(), hookArgvCase{script: "codex-hook.sh"}}
	rows := []struct {
		name   string
		tc     installInFlightShellCase
		event  string
		action string
		output string
	}{
		{"claude PreToolUse deny", claude, "PreToolUse", "block", `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"no"}}`},
		{"claude PreToolUse ask", claude, "PreToolUse", "confirm", `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"sure?"}}`},
		{"claude PermissionRequest deny", claude, "PermissionRequest", "block", `{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"deny","message":"no"}}}`},
		{"claude UserPromptSubmit block", claude, "UserPromptSubmit", "block", `{"decision":"block","reason":"no"}`},
		{"claude PreToolUse allow", claude, "PreToolUse", "allow", `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}`},
		{"codex PreToolUse deny", codex, "PreToolUse", "block", `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"no"}}`},
		{"codex PermissionRequest deny", codex, "PermissionRequest", "block", `{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"deny","message":"no"}}}`},
		{"codex UserPromptSubmit block", codex, "UserPromptSubmit", "block", `{"decision":"block","reason":"no"}`},
		{"codex SessionStart stop", codex, "SessionStart", "block", `{"continue":false,"stopReason":"no"}`},
		{"codex PreToolUse allow", codex, "PreToolUse", "allow", `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}`},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			data := t.TempDir()
			field := "claude_code_output"
			if row.tc.conn.Name() == "codex" {
				field = "codex_output"
			}
			body := `{"action":"` + row.action + `","reason":"policy","` + field + `":` + row.output + `}`
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }))
			t.Cleanup(server.Close)
			hooks := renderPerUserShellHooksAt(t, row.tc, data, "open", strings.TrimPrefix(server.URL, "http://"))
			installNativeGatewayForHookTest(t, data)
			var args []string
			if row.tc.conn.Name() == "codex" {
				args = codexBoundShellHookArgsForTest(t, "codex-hook.sh", row.event)[1:]
			}
			payload := `{"hook_event_name":"` + row.event + `","session_id":"s1","prompt":"hello","tool_name":"Bash","tool_input":{"command":"echo hi"}}`
			code, stdout, stderr := runShellHookWith(t, filepath.Join(hooks, row.tc.invoke.script), args,
				[]string{"HOME=" + data, "DEFENSECLAW_HOME=" + data}, payload)
			if code != 0 || strings.TrimSpace(stdout) != row.output {
				t.Fatalf("exit %d stdout %q stderr %q, want the gateway's object as it is with exit 0", code, stdout, stderr)
			}
		})
	}
}
