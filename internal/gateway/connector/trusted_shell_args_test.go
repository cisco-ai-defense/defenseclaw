// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"runtime"
	"strings"
	"testing"
)

func TestOpenHandsProfileDecodeMapsSDKEventTypes(t *testing.T) {
	for raw, want := range map[string]string{
		"PreToolUse": "pre_tool_use", "PostToolUse": "post_tool_use", "UserPromptSubmit": "user_prompt_submit",
		"Stop": "stop", "SessionStart": "session_start", "SessionEnd": "session_end",
		" PreToolUse ": "pre_tool_use", "pre_tool_use": "", "Unknown": "",
	} {
		if got := openHandsProfileDecode(map[string]interface{}{"event_type": raw}).HookEventName; got != want {
			t.Errorf("event_type %q decoded to %q, want %q", raw, got, want)
		}
	}
	if got := openHandsProfileDecode(map[string]interface{}{"event_type": 3}).HookEventName; got != "" {
		t.Errorf("non-string event_type decoded to %q", got)
	}
	// The contract's block events use the mapped names.
	profile := NewOpenHandsConnector().HookProfile(SetupOpts{})
	if profile.Decode == nil {
		t.Fatal("openhands profile has no event decoder")
	}
	for _, event := range []string{"pre_tool_use", "user_prompt_submit", "stop"} {
		if !stringSliceContains(profile.Capabilities.BlockEvents, event) {
			t.Errorf("block events %v lack %s", profile.Capabilities.BlockEvents, event)
		}
	}
}

type trustedShellArgsCase struct {
	name, tool, args string
	ok               bool
}

func checkTrustedShellArgs(t *testing.T, project func(string, json.RawMessage) (json.RawMessage, bool), want string, cases []trustedShellArgsCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := project(tc.tool, json.RawMessage(tc.args))
			if ok != tc.ok {
				t.Fatalf("ok = %t, want %t (%s)", ok, tc.ok, got)
			}
			if ok && string(got) != want {
				t.Fatalf("projected = %s, want %s", got, want)
			}
			if !ok && string(got) != tc.args {
				t.Fatalf("refused projection changed the arguments: %s", got)
			}
		})
	}
}

func TestOpenHandsTrustedShellArgs(t *testing.T) {
	checkTrustedShellArgs(t, OpenHandsTrustedShellArgs, `{"command":"echo hi > /tmp/x"}`, []trustedShellArgsCase{
		{"sdk-terminal-action", "terminal", `{"command":"echo hi > /tmp/x","is_input":false,"timeout":null,"reset":false,"kind":"TerminalAction"}`, true},
		{"model-labels", "terminal", `{"command":"echo hi > /tmp/x","security_risk":"LOW","summary":"write","timeout":30}`, true},
		{"command-only", "terminal", `{"command":"echo hi > /tmp/x"}`, true},
		// Input to the running process is judged as a shell command.
		{"input-to-running-process", "terminal", `{"command":"echo hi > /tmp/x","is_input":true}`, true},
		{"reset", "terminal", `{"command":"echo hi > /tmp/x","reset":true}`, true},
		{"input-flag-not-bool", "terminal", `{"command":"echo hi > /tmp/x","is_input":"yes"}`, false},
		{"other-kind", "terminal", `{"command":"echo hi > /tmp/x","kind":"FileEditorAction"}`, false},
		{"unknown-field", "terminal", `{"command":"echo hi > /tmp/x","cwd":"/"}`, false},
		{"duplicate-command", "terminal", `{"command":"echo hi > /tmp/x","command":"ls"}`, false},
		{"command-not-string", "terminal", `{"command":["echo","hi"]}`, false},
		{"no-command", "terminal", `{"is_input":false}`, false},
		{"not-an-object", "terminal", `"echo hi"`, false},
		{"other-tool", "file_editor", `{"command":"view","path":"/x"}`, false},
	})
}

func TestAntigravityTrustedShellArgs(t *testing.T) {
	const want = `{"CommandLine":"echo hi > /tmp/x"}`
	// agy's Cwd must be absolute on the host: /work/app is not on Windows.
	cwdArg, wantCwd := `"/work/app"`, "/work/app"
	if runtime.GOOS == "windows" {
		cwdArg, wantCwd = `"C:\\work\\app"`, `C:\work\app`
	}
	project := func(tool string, args json.RawMessage) (json.RawMessage, bool) {
		sent := json.RawMessage(strings.ReplaceAll(string(args), `"/work/app"`, cwdArg))
		out, cwd, ok := AntigravityTrustedShellArgs(tool, sent)
		if !ok && string(out) == string(sent) {
			out = args // refused unchanged: compare with the case as written
		}
		// A refused projection, and text sent to a running command, name no
		// directory.
		want := ""
		if ok && tool == "run_command" {
			want = wantCwd
		}
		if cwd != want {
			t.Errorf("%s cwd = %q (ok %t), want %q", tool, cwd, ok, want)
		}
		return out, ok
	}
	checkTrustedShellArgs(t, project, want, []trustedShellArgsCase{
		{"schema-required", "run_command",
			`{"CommandLine":"echo hi > /tmp/x","Cwd":"/work/app","WaitMsBeforeAsync":500,"toolSummary":"write","toolAction":"Writing"}`, true},
		{"schema-optional", "run_command",
			`{"CommandLine":"echo hi > /tmp/x","Cwd":"/work/app","WaitMsBeforeAsync":0,"IsDaemon":true,"RunPersistent":false,"RequestedTerminalID":"t1","toolSummary":null,"toolAction":"x"}`, true},
		{"plain", "run_command", `{"CommandLine":"echo hi > /tmp/x","Cwd":"/work/app"}`, true},
		// Running outside agy's sandbox still runs the command.
		{"bypass-sandbox", "run_command",
			`{"CommandLine":"echo hi > /tmp/x","Cwd":"/work/app","WaitMsBeforeAsync":500,"BypassSandbox":true,"toolSummary":"write","toolAction":"Writing"}`, true},
		{"bypass-sandbox-not-bool", "run_command", `{"CommandLine":"echo hi > /tmp/x","Cwd":"/work/app","BypassSandbox":"yes"}`, false},
		{"relative-cwd", "run_command", `{"CommandLine":"echo hi > /tmp/x","Cwd":"work/app"}`, false},
		{"unknown-field", "run_command", `{"CommandLine":"echo hi > /tmp/x","Cwd":"/work/app","Env":{"A":"1"}}`, false},
		{"duplicate-command", "run_command", `{"CommandLine":"ls","CommandLine":"echo hi > /tmp/x","Cwd":"/work/app"}`, false},
		{"command-not-string", "run_command", `{"CommandLine":["echo","hi"],"Cwd":"/work/app"}`, false},
		{"cwd-not-string", "run_command", `{"CommandLine":"echo hi > /tmp/x","Cwd":1}`, false},
		{"wait-not-number", "run_command", `{"CommandLine":"echo hi > /tmp/x","Cwd":"/work/app","WaitMsBeforeAsync":"soon"}`, false},
		{"daemon-not-bool", "run_command", `{"CommandLine":"echo hi > /tmp/x","Cwd":"/work/app","IsDaemon":"yes"}`, false},
		{"no-command", "run_command", `{"Cwd":"/work/app","WaitMsBeforeAsync":500}`, false},
		{"not-an-object", "run_command", `"echo hi"`, false},
		{"other-tool", "view_file", `{"CommandLine":"echo hi > /tmp/x","Cwd":"/work/app"}`, false},
		{"input", "send_command_input", `{"CommandId":"c1","Input":"echo hi > /tmp/x","WaitMs":500}`, true},
		{"labels-and-unknown-fields", "send_command_input", `{"CommandId":"c1","Input":"echo hi > /tmp/x","Terminate":false,"toolSummary":"s","Extra":1}`, true},
		{"terminate-only", "send_command_input", `{"CommandId":"c1","Terminate":true}`, false},
		{"empty-input", "send_command_input", `{"CommandId":"c1","Input":"  "}`, false},
		{"input-not-string", "send_command_input", `{"CommandId":"c1","Input":["echo"]}`, false},
		{"duplicate-input", "send_command_input", `{"Input":"ls","Input":"echo hi > /tmp/x"}`, false},
	})
	// Without Cwd (or with a null one) the command runs in the session's
	// directory: no cwd comes back.
	for _, args := range []string{`{"CommandLine":"ls","toolAction":"x"}`, `{"CommandLine":"ls","Cwd":null}`} {
		got, cwd, ok := AntigravityTrustedShellArgs("run_command", json.RawMessage(args))
		if !ok || string(got) != `{"CommandLine":"ls"}` || cwd != "" {
			t.Fatalf("%s: projection = %s, cwd %q, %t", args, got, cwd, ok)
		}
	}
}

func TestHermesTrustedShellArgs(t *testing.T) {
	checkTrustedShellArgs(t, HermesTrustedShellArgs, `{"command":"echo hi > /tmp/x"}`, []trustedShellArgsCase{
		{"submit", "process", `{"action":"submit","session_id":"p1","data":"echo hi > /tmp/x"}`, true},
		{"write", "process", `{"action":"write","session_id":"p1","data":"echo hi > /tmp/x"}`, true},
		{"poll", "process", `{"action":"poll","session_id":"p1"}`, false},
		{"kill-with-data", "process", `{"action":"kill","session_id":"p1","data":"echo hi > /tmp/x"}`, false},
		{"no-data", "process", `{"action":"submit","session_id":"p1"}`, false},
		{"duplicate-data", "process", `{"action":"submit","data":"ls","data":"echo hi > /tmp/x"}`, false},
		{"other-tool", "terminal", `{"action":"submit","data":"echo hi > /tmp/x"}`, false},
	})
}

func TestTrustedShellArgs(t *testing.T) {
	for _, tc := range []struct {
		name, connector, tool, args, want, cwd string
		ok                                     bool
	}{
		{"opencode-bash", "opencode", "bash", `{"command":"echo hi > /tmp/x","timeout":120000,"workdir":"/work/app/sub"}`,
			`{"command":"echo hi > /tmp/x","timeout":120000}`, "/work/app/sub", true},
		{"opencode-relative", "opencode", "bash", `{"command":"ls","workdir":"sub"}`, `{"command":"ls"}`, "sub", true},
		{"hermes-terminal", "hermes", "terminal", `{"command":"ls","workdir":"/tmp","background":false}`,
			`{"command":"ls"}`, "/tmp", true},
		{"hermes-controls", "hermes", "terminal",
			`{"command":"ls","background":true,"timeout":60,"pty":true,"notify":true,"notify_on_complete":false,"watch_patterns":["done"]}`,
			`{"command":"ls"}`, "", true},
		{"hermes-notify-patterns", "hermes", "terminal", `{"command":"ls","notify":["a","b"]}`, `{"command":"ls"}`, "", true},
		{"amp-timeout", "amp", "shell_command", `{"command":"ls","workdir":"/w","timeout_ms":10000}`, `{"command":"ls"}`, "/w", true},
		{"devin-controls", "devin", "exec", `{"command":"ls","timeout":0,"tty":false}`, `{"command":"ls"}`, "", true},
		{"kiro-summary", "kiro", "execute_bash", `{"command":"ls","summary":"list","working_dir":"/w"}`, `{"command":"ls"}`, "/w", true},
		{"copilot-sync", "copilot", "bash", `{"command":"ls","description":"list","mode":"sync","initial_wait":30}`, `{"command":"ls"}`, "", true},
		{"copilot-async", "copilot", "powershell", `{"command":"ls","description":"list","mode":"async","detach":true}`, `{"command":"ls"}`, "", true},
		// Arguments that change where or how the command runs stay for the
		// parser, which does not prove them.
		{"devin-shell-and-env", "devin", "exec", `{"command":"ls","shell_id":"s1","env":{"A":"1"},"shell_flavor":"zsh","timeout":5}`,
			`{"command":"ls","env":{"A":"1"},"shell_flavor":"zsh","shell_id":"s1"}`, "", true},
		{"copilot-reused-shell", "copilot", "bash", `{"command":"ls","mode":"sync","shellId":"s1"}`, `{"command":"ls","shellId":"s1"}`, "", true},
		{"control-wrong-type", "hermes", "terminal", `{"command":"ls","background":"yes"}`, "", "", false},
		{"notify-wrong-type", "hermes", "terminal", `{"command":"ls","notify":[1]}`, "", "", false},
		{"label-wrong-type", "copilot", "bash", `{"command":"ls","description":["x"]}`, "", "", false},
		{"amp-shell-command", "amp", "shell_command", `{"command":"ls","workdir":"/w"}`, `{"command":"ls"}`, "/w", true},
		{"cursor-shell", "cursor", "Shell", `{"command":"ls","cwd":"/w","timeout":30000}`, `{"command":"ls","timeout":30000}`, "/w", true},
		// Cursor reports "" when the model named no directory.
		{"cursor-shell-no-dir", "cursor", "Shell", `{"command":"ls","cwd":""}`, `{"command":"ls"}`, "", true},
		{"devin-exec", "devin", "exec", `{"command":"ls","workdir":"/w"}`, `{"command":"ls"}`, "/w", true},
		{"kiro-shell", "kiro", "shell", `{"command":"ls","working_dir":"/w"}`, `{"command":"ls"}`, "/w", true},
		{"kiro-execute-bash", "kiro", "execute_bash", `{"command":"ls","working_dir":"/w"}`, `{"command":"ls"}`, "/w", true},
		{"null-dir", "opencode", "bash", `{"command":"ls","workdir":null}`, `{"command":"ls"}`, "", true},
		{"operators-kept", "opencode", "bash", `{"command":"a && b > c","workdir":"/w"}`, `{"command":"a && b > c"}`, "/w", true},
		// Refused: the arguments are left for the parser to judge.
		{"no-dir", "opencode", "bash", `{"command":"ls"}`, "", "", false},
		{"dir-not-string", "opencode", "bash", `{"command":"ls","workdir":["/w"]}`, "", "", false},
		{"duplicate-key", "opencode", "bash", `{"command":"ls","workdir":"/a","workdir":"/b"}`, "", "", false},
		{"not-an-object", "opencode", "bash", `"ls"`, "", "", false},
		{"other-key", "kiro", "shell", `{"command":"ls","workdir":"/w"}`, "", "", false},
		{"other-tool", "opencode", "read", `{"filePath":"/x","workdir":"/w"}`, "", "", false},
		// Shell tools that name no directory are left alone.
		{"claudecode", "claudecode", "Bash", `{"command":"ls","cwd":"/w"}`, "", "", false},
		{"copilot", "copilot", "bash", `{"command":"ls","cwd":"/w"}`, "", "", false},
		{"openhands", "openhands", "terminal", `{"command":"ls","cwd":"/w"}`, "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, cwd, ok := TrustedShellArgs(tc.connector, tc.tool, json.RawMessage(tc.args))
			if ok != tc.ok {
				t.Fatalf("ok = %t, want %t (%s)", ok, tc.ok, got)
			}
			if !ok {
				if string(got) != tc.args || cwd != "" {
					t.Fatalf("refused projection = %s, cwd %q", got, cwd)
				}
				return
			}
			if string(got) != tc.want || cwd != tc.cwd {
				t.Fatalf("projection = %s, cwd %q; want %s, %q", got, cwd, tc.want, tc.cwd)
			}
		})
	}
}

func TestCursorTrustedShellArgs(t *testing.T) {
	const payload = `{"conversation_id":"c1","generation_id":"g1","model":"m","hook_event_name":"beforeShellExecution",` +
		`"cursor_version":"2026.07.23-e383d2b","workspace_roots":["/w"],"command":"echo hi > /tmp/x","cwd":"/w/sub","sandbox":false}`
	got, cwd, ok := CursorTrustedShellArgs("beforeShellExecution", json.RawMessage(payload))
	if !ok || string(got) != `{"command":"echo hi > /tmp/x"}` || cwd != "/w/sub" {
		t.Fatalf("projection = %s, cwd %q, %t", got, cwd, ok)
	}
	if _, cwd, ok := CursorTrustedShellArgs("beforeShellExecution", json.RawMessage(`{"command":"ls"}`)); !ok || cwd != "" {
		t.Fatalf("without cwd: cwd %q, %t", cwd, ok)
	}
	for name, tc := range map[string]struct{ event, payload string }{
		"other-event":       {"preToolUse", payload},
		"mcp-event":         {"beforeMCPExecution", payload},
		"no-command":        {"beforeShellExecution", `{"cwd":"/w"}`},
		"blank-command":     {"beforeShellExecution", `{"command":"  ","cwd":"/w"}`},
		"command-not-text":  {"beforeShellExecution", `{"command":["ls"],"cwd":"/w"}`},
		"cwd-not-string":    {"beforeShellExecution", `{"command":"ls","cwd":1}`},
		"duplicate-command": {"beforeShellExecution", `{"command":"ls","command":"echo hi > /tmp/x"}`},
	} {
		t.Run(name, func(t *testing.T) {
			got, cwd, ok := CursorTrustedShellArgs(tc.event, json.RawMessage(tc.payload))
			if ok || string(got) != tc.payload || cwd != "" {
				t.Fatalf("projection = %s, cwd %q, %t; want refused", got, cwd, ok)
			}
		})
	}
}

func TestShellCommandArgs(t *testing.T) {
	for _, tc := range []struct {
		name, connector, tool, args, want string
	}{
		{"unlisted", "opencode", "bash", `{"command":"echo hi > /tmp/x","workdir":"/w","dc_unlisted_arg":"x"}`, `{"command":"echo hi > /tmp/x"}`},
		{"mistyped", "hermes", "terminal", `{"command":"ls","background":"yes"}`, `{"command":"ls"}`},
		{"no-listed", "copilot", "bash", `{"command":"ls","dc_unlisted_arg":1}`, `{"command":"ls"}`},
		{"exact", "devin", "exec", `{"command":"ls"}`, `{"command":"ls"}`},
		{"argv", "codex", "Bash", `{"command":["bash","-lc","ls"],"dc_unlisted_arg":1}`, `{"command":["bash","-lc","ls"]}`},
		{"repeated", "kiro", "shell", `{"command":"ls","command":"echo hi > /tmp/x"}`, `{"command":"echo hi > /tmp/x"}`},
		{"agy", "antigravity", "run_command", `{"CommandLine":"a && b","Cwd":7,"dc_unlisted_arg":1}`, `{"CommandLine":"a && b"}`},
		{"openhands", "openhands", "terminal", `{"command":"ls","kind":"Other"}`, `{"command":"ls"}`},
		{"omnigent", "omnigent", "sys_os_shell", `{"command":"ls","dc_unlisted_arg":1}`, `{"command":"ls"}`},
		{"claudecode", "claudecode", "Bash", `{"command":"ls","dc_unlisted_arg":1}`, `{"command":"ls"}`},
		{"connector-case", " Cursor ", "Shell", `{"command":"ls","cwd":7}`, `{"command":"ls"}`},
		// Refused.
		{"blank", "opencode", "bash", `{"command":"  ","dc_unlisted_arg":1}`, ""},
		{"null", "opencode", "bash", `{"command":null}`, ""},
		{"not-text", "opencode", "bash", `{"command":7}`, ""},
		{"empty-argv", "opencode", "bash", `{"command":[]}`, ""},
		{"argv-not-text", "opencode", "bash", `{"command":["ls",1]}`, ""},
		{"no-command", "opencode", "bash", `{"workdir":"/w"}`, ""},
		{"other-key", "antigravity", "run_command", `{"command":"ls"}`, ""},
		{"not-an-object", "opencode", "bash", `"ls"`, ""},
		{"invalid-json", "opencode", "bash", `{"command":"ls"`, ""},
		{"other-tool", "opencode", "read", `{"command":"ls"}`, ""},
		{"tool-case", "cursor", "shell", `{"command":"ls"}`, ""},
		{"other-connector", "zed", "bash", `{"command":"ls"}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ShellCommandArgs(tc.connector, tc.tool, json.RawMessage(tc.args))
			if ok != (tc.want != "") || string(got) != tc.want {
				t.Fatalf("ShellCommandArgs = %s, %t; want %s", got, ok, tc.want)
			}
		})
	}
	// Every shell tool the trusted-action projection reads has its command
	// named.
	for connectorName, tools := range trustedShellTools {
		for tool := range tools {
			if shellCommandKeys[connectorName][tool] == "" {
				t.Errorf("%s %s names no command key", connectorName, tool)
			}
		}
	}
}

func TestCursorShellCommandArgs(t *testing.T) {
	got, ok := CursorShellCommandArgs("beforeShellExecution", json.RawMessage(`{"command":"echo hi > /tmp/x","cwd":7,"sandbox":false}`))
	if !ok || string(got) != `{"command":"echo hi > /tmp/x"}` {
		t.Fatalf("projection = %s, %t", got, ok)
	}
	for name, tc := range map[string]struct{ event, payload string }{
		"other-event":   {"preToolUse", `{"command":"ls"}`},
		"no-command":    {"beforeShellExecution", `{"cwd":"/w"}`},
		"blank-command": {"beforeShellExecution", `{"command":" "}`},
	} {
		t.Run(name, func(t *testing.T) {
			if got, ok := CursorShellCommandArgs(tc.event, json.RawMessage(tc.payload)); ok || got != nil {
				t.Fatalf("projection = %s, %t; want refused", got, ok)
			}
		})
	}
}
