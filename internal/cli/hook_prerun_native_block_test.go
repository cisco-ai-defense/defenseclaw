// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0982 and its class: a native hook command that failed before Run (an
// unknown flag, a malformed value, a stray argument) exited 1 for every
// connector but Kiro. Claude Code, Codex, Devin, Hermes, Copilot and
// Antigravity run the call on that status, during an install too. Where the
// policy is closed (the installer holds the data directory, or the mode is
// closed) the hook now answers with the connector's own block for the
// event it is registered for: Codex's object with exit 0, Claude Code's,
// Devin's and Kiro's exit 2, Hermes' block directive, Copilot's and
// Antigravity's deny, Cursor's. Fail mode open without an install keeps 1.
func TestHookPreRunFailureAnswersWithTheConnectorsNativeBlock(t *testing.T) {
	type form struct {
		connector, event string
		payload          string
		// blocks reads the answer as the agent does.
		blocks func(code int, stdout string) bool
	}
	exit2 := func(code int, _ string) bool { return code == 2 }
	jsonField := func(path ...string) func(int, string) bool {
		return func(code int, stdout string) bool {
			if code != 0 {
				return false
			}
			var answer map[string]any
			if json.Unmarshal([]byte(strings.TrimSpace(stdout)), &answer) != nil {
				return false
			}
			var value any = answer
			for _, key := range path[:len(path)-1] {
				object, _ := value.(map[string]any)
				value = object[key]
			}
			return value == path[len(path)-1]
		}
	}
	forms := []form{
		{"claudecode", "PreToolUse", `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`, func(code int, stdout string) bool {
			return code == 2 || jsonField("hookSpecificOutput", "permissionDecision", "deny")(code, stdout)
		}},
		{"codex", "UserPromptSubmit", `{"hook_event_name":"UserPromptSubmit","prompt":"hi"}`, jsonField("decision", "block")},
		{"codex", "PreToolUse", `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`, jsonField("hookSpecificOutput", "permissionDecision", "deny")},
		{"codex", "PermissionRequest", `{"hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{"command":"ls"}}`, jsonField("hookSpecificOutput", "decision", "behavior", "deny")},
		{"devin", "PreToolUse", `{"hook_event_name":"PreToolUse","tool_name":"exec","tool_input":{"command":"ls"}}`, exit2},
		{"kiro", "PreToolUse", `{"hook_event_name":"preToolUse","tool_name":"execute_bash","tool_input":{"command":"ls"}}`, exit2},
		{"hermes", "", `{"hook_event_name":"pre_tool_call","tool_name":"terminal","tool_input":{"command":"ls"}}`, jsonField("action", "block")},
		{"copilot", "preToolUse", `{"toolName":"bash","toolArgs":"{\"command\":\"ls\"}"}`, jsonField("permissionDecision", "deny")},
		{"antigravity", "PreToolUse", `{"tool_name":"run_command","tool_input":{"CommandLine":"ls"}}`, jsonField("decision", "deny")},
		{"cursor", "beforeShellExecution", `{"hook_event_name":"beforeShellExecution","command":"ls"}`, func(code int, stdout string) bool {
			return code == 2 || strings.Contains(stdout, `"deny"`)
		}},
	}
	failures := []struct {
		name string
		args []string
	}{
		{"unknown flag", []string{"--not-a-hook-flag"}},
		{"stray argument", []string{"stray"}},
		{"unlisted hook surface", []string{"--hook-surface", "v9"}},
	}
	modes := []struct {
		name, failMode string
		install, want  bool
	}{
		{"fail mode open during an install", "open", true, true},
		{"fail mode closed", "closed", false, true},
		{"fail mode open", "open", false, false},
	}
	for _, f := range forms {
		for _, failure := range failures {
			for _, mode := range modes {
				t.Run(f.connector+"/"+f.event+"/"+failure.name+"/"+mode.name, func(t *testing.T) {
					home := t.TempDir()
					t.Setenv("DEFENSECLAW_HOME", home)
					t.Setenv("DEFENSECLAW_FAIL_MODE", "")
					if mode.install {
						if err := os.Mkdir(filepath.Join(home, ".install.lock"), 0o700); err != nil {
							t.Fatal(err)
						}
					}
					args := []string{"--connector", f.connector, "--fail-mode", mode.failMode}
					if f.event != "" {
						args = append(args, "--event", f.event)
					}
					if f.connector == "codex" {
						args = append(args, "--hook-contract", "codex-hooks-v4")
					}
					args = append(args, failure.args...)
					previousArgs, previousIO := hookRawArgs, hookFailureIO
					var stdout, stderr bytes.Buffer
					hookRawArgs = func() []string { return args }
					hookFailureIO = func() (io.Reader, io.Writer, io.Writer) {
						return strings.NewReader(f.payload), &stdout, &stderr
					}
					t.Cleanup(func() { hookRawArgs, hookFailureIO = previousArgs, previousIO })
					cmd := newHookCmd()
					cmd.SetArgs(args)
					cmd.SetOut(io.Discard)
					cmd.SetErr(io.Discard)
					cmd.SilenceUsage = true
					cmd.SilenceErrors = true
					err := cmd.Execute()
					if err == nil {
						t.Fatalf("hook %v succeeded, want a usage failure", args)
					}
					code := commandExitCode(err)
					if got := f.blocks(code, stdout.String()); got != mode.want {
						t.Fatalf("hook %v: exit %d stdout %q stderr %q: blocks=%v, want %v", args, code, stdout.String(), stderr.String(), got, mode.want)
					}
					if !mode.want && (code != 1 || stdout.Len() != 0) {
						t.Fatalf("hook %v in fail mode open: exit %d stdout %q, want the usage failure's 1 and no answer", args, code, stdout.String())
					}
				})
			}
		}
	}
}
