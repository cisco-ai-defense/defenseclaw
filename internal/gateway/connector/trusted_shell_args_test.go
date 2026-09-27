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
		{"input-to-running-process", "terminal", `{"command":"echo hi > /tmp/x","is_input":true}`, false},
		{"reset", "terminal", `{"command":"echo hi > /tmp/x","reset":true}`, false},
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
	const want = `{"CommandLine":"echo hi > /tmp/x","Cwd":"/work/app"}`
	checkTrustedShellArgs(t, AntigravityTrustedShellArgs, want, []trustedShellArgsCase{
		{"schema-required", "run_command",
			`{"CommandLine":"echo hi > /tmp/x","Cwd":"/work/app","WaitMsBeforeAsync":500,"toolSummary":"write","toolAction":"Writing"}`, true},
		{"schema-optional", "run_command",
			`{"CommandLine":"echo hi > /tmp/x","Cwd":"/work/app","WaitMsBeforeAsync":0,"IsDaemon":true,"RunPersistent":false,"RequestedTerminalID":"t1","toolSummary":null,"toolAction":"x"}`, true},
		{"plain", "run_command", `{"CommandLine":"echo hi > /tmp/x","Cwd":"/work/app"}`, true},
		{"unknown-field", "run_command", `{"CommandLine":"echo hi > /tmp/x","Cwd":"/work/app","Env":{"A":"1"}}`, false},
		{"duplicate-command", "run_command", `{"CommandLine":"ls","CommandLine":"echo hi > /tmp/x","Cwd":"/work/app"}`, false},
		{"command-not-string", "run_command", `{"CommandLine":["echo","hi"],"Cwd":"/work/app"}`, false},
		{"cwd-not-string", "run_command", `{"CommandLine":"echo hi > /tmp/x","Cwd":1}`, false},
		{"wait-not-number", "run_command", `{"CommandLine":"echo hi > /tmp/x","Cwd":"/work/app","WaitMsBeforeAsync":"soon"}`, false},
		{"daemon-not-bool", "run_command", `{"CommandLine":"echo hi > /tmp/x","Cwd":"/work/app","IsDaemon":"yes"}`, false},
		{"no-command", "run_command", `{"Cwd":"/work/app","WaitMsBeforeAsync":500}`, false},
		{"not-an-object", "run_command", `"echo hi"`, false},
		{"other-tool", "view_file", `{"CommandLine":"echo hi > /tmp/x","Cwd":"/work/app"}`, false},
	})
	// Without Cwd the projection carries the command alone.
	got, ok := AntigravityTrustedShellArgs("run_command", json.RawMessage(`{"CommandLine":"ls","toolAction":"x"}`))
	if !ok || string(got) != `{"CommandLine":"ls"}` {
		t.Fatalf("projection without Cwd = %s, %t", got, ok)
	}
}
