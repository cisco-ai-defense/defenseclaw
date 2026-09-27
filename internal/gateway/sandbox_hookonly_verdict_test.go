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

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// TestAgentHookTrustedActionShellShapes pins the shell shapes that did not
// parse completely, so command rules could not prove a trusted action and a
// CRITICAL finding stayed an allowed candidate: OmniGent's sys_os_shell tool
// name, OpenHands' TerminalAction fields, and agy's run_command fields,
// including a Cwd other than the session's working directory, and the
// working-directory argument of the other shell tools that name one.
func TestAgentHookTrustedActionShellShapes(t *testing.T) {
	const command = `{"command":"echo DCE2E-BLOCK-MARKER > /tmp/dce2e-blocked.txt"}`
	for _, tc := range []struct {
		name, connector, tool, args string
	}{
		{"omnigent-sys-os-shell", "omnigent", "sys_os_shell", command},
		{"openhands-terminal-action", "openhands", "terminal",
			`{"command":"echo DCE2E-BLOCK-MARKER > /tmp/dce2e-blocked.txt","is_input":false,"timeout":null,"reset":false,"kind":"TerminalAction"}`},
		{"antigravity-run-command", "antigravity", "run_command",
			`{"CommandLine":"echo DCE2E-BLOCK-MARKER > /tmp/dce2e-blocked.txt","Cwd":"/work/app","WaitMsBeforeAsync":500,"toolSummary":"write marker","toolAction":"Writing marker"}`},
		{"antigravity-other-cwd", "antigravity", "run_command",
			`{"CommandLine":"echo DCE2E-BLOCK-MARKER > /tmp/dce2e-blocked.txt","Cwd":"/tmp"}`},
		// The working-directory argument of the other shell tools that have
		// one, and their control arguments (connector.TrustedShellArgs).
		{"opencode-bash-workdir", "opencode", "bash",
			`{"command":"echo DCE2E-BLOCK-MARKER > /tmp/dce2e-blocked.txt","timeout":120000,"workdir":"/tmp"}`},
		{"hermes-terminal-workdir", "hermes", "terminal",
			`{"command":"echo DCE2E-BLOCK-MARKER > /tmp/dce2e-blocked.txt","workdir":"/tmp"}`},
		{"amp-shell-command-workdir", "amp", "shell_command",
			`{"command":"echo DCE2E-BLOCK-MARKER > /tmp/dce2e-blocked.txt","workdir":"/tmp"}`},
		{"cursor-shell-cwd", "cursor", "Shell",
			`{"command":"echo DCE2E-BLOCK-MARKER > /tmp/dce2e-blocked.txt","cwd":"/tmp","timeout":30000}`},
		{"cursor-shell-no-cwd", "cursor", "Shell",
			`{"command":"echo DCE2E-BLOCK-MARKER > /tmp/dce2e-blocked.txt","cwd":""}`},
		{"devin-exec-workdir", "devin", "exec",
			`{"command":"echo DCE2E-BLOCK-MARKER > /tmp/dce2e-blocked.txt","workdir":"/tmp"}`},
		{"kiro-shell-working-dir", "kiro", "shell",
			`{"command":"echo DCE2E-BLOCK-MARKER > /tmp/dce2e-blocked.txt","working_dir":"/tmp"}`},
		{"hermes-terminal-controls", "hermes", "terminal",
			`{"command":"echo DCE2E-BLOCK-MARKER > /tmp/dce2e-blocked.txt","background":true,"timeout":60,"pty":false,"notify":["done"]}`},
		{"amp-shell-command-timeout", "amp", "shell_command",
			`{"command":"echo DCE2E-BLOCK-MARKER > /tmp/dce2e-blocked.txt","workdir":"/tmp","timeout_ms":10000}`},
		{"devin-exec-controls", "devin", "exec",
			`{"command":"echo DCE2E-BLOCK-MARKER > /tmp/dce2e-blocked.txt","timeout":0,"tty":false}`},
		{"kiro-execute-bash-summary", "kiro", "execute_bash",
			`{"command":"echo DCE2E-BLOCK-MARKER > /tmp/dce2e-blocked.txt","summary":"write marker","working_dir":"/tmp"}`},
		{"copilot-bash-controls", "copilot", "bash",
			`{"command":"echo DCE2E-BLOCK-MARKER > /tmp/dce2e-blocked.txt","description":"write marker","mode":"sync","initial_wait":30}`},
		{"copilot-bash-async", "copilot", "bash",
			`{"command":"echo DCE2E-BLOCK-MARKER > /tmp/dce2e-blocked.txt","description":"write marker","mode":"async","detach":true}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const sessionCWD = "/work/app/sub"
			raw := actionfacts.Analyze(actionfacts.Input{Tool: tc.tool, Args: json.RawMessage(tc.args), CWD: sessionCWD})
			if raw.Parse.Status == actionfacts.StatusComplete {
				t.Skip("the raw shape now parses completely upstream; the mapping is redundant")
			}
			args, toolCWD := agentHookTrustedActionArgs(tc.connector, tc.tool, json.RawMessage(tc.args))
			mapped := actionfacts.Analyze(actionfacts.Input{
				Tool: agentHookTrustedActionTool(tc.connector, tc.tool, "linux"),
				Args: args,
				CWD:  agentHookTrustedActionCWD(context.Background(), sessionCWD, toolCWD),
			})
			if mapped.Parse.Status != actionfacts.StatusComplete {
				t.Fatalf("mapped parse = %+v, want complete", mapped.Parse)
			}
		})
	}
	// Scoped to the one connector each: nobody else's tool or arguments move.
	if got := agentHookTrustedActionTool("hermes", "sys_os_shell", "linux"); got != "sys_os_shell" {
		t.Errorf("hermes sys_os_shell = %q, want passthrough", got)
	}
	args := json.RawMessage(`{"command":"ls","is_input":false}`)
	if got, cwd := agentHookTrustedActionArgs("hermes", "terminal", args); string(got) != string(args) || cwd != "" {
		t.Errorf("hermes terminal args = %s (cwd %q), want passthrough", got, cwd)
	}
	// Input to a running process is judged as shell input.
	if got, _ := agentHookTrustedActionArgs("openhands", "terminal", json.RawMessage(`{"command":"ls","is_input":true}`)); string(got) != `{"command":"ls"}` {
		t.Errorf("input to a running process was not projected: %s", got)
	}
	// The tool call's directory replaces the session's, mapped the same way
	// (on the host: an existing absolute directory, symlinks resolved).
	if got := agentHookTrustedActionCWD(context.Background(), "/work/app", ""); got != "/work/app" {
		t.Errorf("no tool cwd = %q, want the request's", got)
	}
	dir := t.TempDir()
	want, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := agentHookTrustedActionCWD(context.Background(), "/work/app", dir); got != want {
		t.Errorf("tool cwd = %q, want %q", got, want)
	}
	if got := agentHookTrustedActionCWD(context.Background(), "/work/app", filepath.Join(dir, "missing")); got != "" {
		t.Errorf("missing tool cwd = %q, want none", got)
	}
	// A relative directory is resolved against the session's; one the
	// gateway cannot place is none.
	if err := os.Mkdir(filepath.Join(want, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := agentHookTrustedActionCWD(context.Background(), want, "sub"); got != filepath.Join(want, "sub") {
		t.Errorf("relative tool cwd = %q, want %q", got, filepath.Join(want, "sub"))
	}
	for _, tc := range []struct{ request, tool string }{{"", "sub"}, {want, "~/sub"}, {want, "missing"}} {
		if got := agentHookTrustedActionCWD(context.Background(), tc.request, tc.tool); got != "" {
			t.Errorf("tool cwd %q in %q = %q, want none", tc.tool, tc.request, got)
		}
	}
}

// TestSandboxHookOnlyShellCallsAreJudged pins that the shell tool call each
// sandboxed hook-only harness sends, in the exact payload shape the harness
// produces, reaches the command rules through the sandbox ingress: the E2E
// marker rule must block it with its plain reason, and the verdict must be
// rendered in the harness's own block shape.
func TestSandboxHookOnlyShellCallsAreJudged(t *testing.T) {
	installSandboxMarkerRules(t)
	var mu sync.Mutex
	var decisions []SandboxHookDecision
	// Mount mode, as the E2E runs: the request working directory /work/app
	// maps to a host directory.
	project := t.TempDir()
	f := newSandboxIngressFixture(t, func(c *SandboxIngressConfig) {
		c.OnHookDecision = func(d SandboxHookDecision) {
			mu.Lock()
			defer mu.Unlock()
			decisions = append(decisions, d)
		}
	})
	const command = "echo DCE2E-BLOCK-MARKER > /tmp/dce2e-blocked.txt"
	want := "Blocked by DefenseClaw rule E2E-SANDBOX-MARKER: E2E sandbox marker command. " + sandboxDefaultRemediation
	for i, tc := range []struct {
		connector, version, contract, path, body, tool string
		headers                                        []string
		// output checks the harness-specific rendering of the block.
		output func(t *testing.T, resp map[string]interface{})
	}{
		{
			connector: "hermes", version: "0.19.0", contract: "hermes-hooks-v1", path: "/api/v1/hermes/hook", tool: "terminal",
			body: `{"hook_event_name":"pre_tool_call","tool_name":"terminal","tool_input":{"command":"` + command + `"},` +
				`"session_id":"20260927_1","cwd":"/work/app","extra":{"tool_call_id":"call_1","task_id":"t1"}}`,
			output: func(t *testing.T, resp map[string]interface{}) {
				out, _ := resp["hook_output"].(map[string]interface{})
				if out["decision"] != "block" || out["reason"] != want {
					t.Fatalf("hermes hook_output = %v", out)
				}
			},
		},
		{
			connector: "openhands", version: "1.16.0", contract: "openhands-hooks-v1", path: "/api/v1/openhands/hook", tool: "terminal",
			body: `{"event_type":"PreToolUse","tool_name":"terminal","tool_input":{"command":"` + command + `","is_input":false,` +
				`"timeout":null,"reset":false,"kind":"TerminalAction"},"tool_response":null,"message":null,` +
				`"session_id":"c1c2b756-f8e9-4e9d-97d0-2c27ecb6c3d1","working_dir":"/work/app","metadata":{}}`,
			output: func(t *testing.T, resp map[string]interface{}) {
				out, _ := resp["hook_output"].(map[string]interface{})
				if out["decision"] != "deny" || out["reason"] != want {
					t.Fatalf("openhands hook_output = %v", out)
				}
			},
		},
		{
			connector: "antigravity", version: "1.2.12", contract: "antigravity-hooks-v2", path: "/api/v1/antigravity/hook", tool: "run_command",
			headers: []string{"X-DefenseClaw-Antigravity-Event", "PreToolUse"},
			// agy 1.2's run_command schema requires WaitMsBeforeAsync,
			// toolSummary and toolAction next to CommandLine and Cwd.
			body: `{"conversationId":"c1","workspacePaths":["/work/app"],"stepIdx":3,"toolCall":{"name":"run_command","args":{` +
				`"CommandLine":"` + command + `","Cwd":"/tmp","WaitMsBeforeAsync":500,` +
				`"toolSummary":"write marker","toolAction":"Writing marker"}}}`,
			output: func(t *testing.T, resp map[string]interface{}) {
				out, _ := resp["hook_output"].(map[string]interface{})
				if out["decision"] != "deny" {
					t.Fatalf("antigravity hook_output = %v", out)
				}
			},
		},
		// Text sent to a running process is judged as shell input.
		{
			connector: "openhands", version: "1.16.0", contract: "openhands-hooks-v1", path: "/api/v1/openhands/hook", tool: "terminal",
			body: `{"event_type":"PreToolUse","tool_name":"terminal","tool_input":{"command":"` + command + `","is_input":true,` +
				`"timeout":null,"reset":false,"kind":"TerminalAction"},"session_id":"c1c2b756-f8e9-4e9d-97d0-2c27ecb6c3d1","working_dir":"/work/app"}`,
		},
		{
			connector: "antigravity", version: "1.2.12", contract: "antigravity-hooks-v2", path: "/api/v1/antigravity/hook", tool: "send_command_input",
			headers: []string{"X-DefenseClaw-Antigravity-Event", "PreToolUse"},
			body: `{"conversationId":"c1","workspacePaths":["/work/app"],"stepIdx":4,"toolCall":{"name":"send_command_input","args":{` +
				`"CommandId":"cmd-1","Input":"` + command + `","WaitMs":500,"toolSummary":"type","toolAction":"Typing"}}}`,
		},
		{
			connector: "hermes", version: "0.19.0", contract: "hermes-hooks-v1", path: "/api/v1/hermes/hook", tool: "process",
			body: `{"hook_event_name":"pre_tool_call","tool_name":"process","tool_input":{"action":"submit","session_id":"proc_1","data":"` + command + `"},` +
				`"session_id":"20260927_1","cwd":"/work/app","extra":{"tool_call_id":"call_2","task_id":"t1"}}`,
		},
		{
			connector: "omnigent", version: "0.13.0", contract: "omnigent-custom-policy-v1", path: "/api/v1/omnigent/hook", tool: "sys_os_shell",
			body: `{"hook_event_name":"PreToolUse","omnigent_event_type":"tool_call","agent_name":"OmniGent","agent_type":"omnigent",` +
				`"omnigent_actor_client_id":"","model":"mock-model","omnigent_session_id_status":"unavailable_in_v0.7_policy_event",` +
				`"tool_name":"sys_os_shell","tool_input":{"command":"` + command + `"}}`,
		},
	} {
		t.Run(tc.connector+"-"+tc.tool, func(t *testing.T) {
			_, token, err := f.store.Mint(sandboxauth.Spec{
				SandboxName: "dc-" + tc.connector + "-" + strings.ReplaceAll(tc.tool, "_", "-") + "-" + strconv.Itoa(i), Connector: tc.connector,
				AgentVersion: tc.version, HookContractID: tc.contract, PolicyProfile: "open",
				Workdir: sandboxauth.Workdir{Mode: sandboxauth.WorkdirMount,
					Mounts: []sandboxauth.Mount{{SandboxPath: "/work/app", HostPath: project}}},
				HostUser: sandboxauth.HostUser{UID: "1000", Name: "dev"},
			})
			if err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			decisions = nil
			mu.Unlock()
			rec := f.do(t, http.MethodPost, tc.path, token, tc.body, tc.headers...)
			if rec.Code != http.StatusOK {
				t.Fatalf("hook: %d %s", rec.Code, rec.Body.String())
			}
			var resp map[string]interface{}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			if resp["action"] != "block" || resp["reason"] != want {
				t.Fatalf("%s verdict = %s", tc.connector, rec.Body.String())
			}
			if tc.output != nil {
				tc.output(t, resp)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(decisions) != 1 || decisions[0].Action != "block" || decisions[0].Tool != tc.tool {
				t.Fatalf("decisions = %+v", decisions)
			}
		})
	}
}
