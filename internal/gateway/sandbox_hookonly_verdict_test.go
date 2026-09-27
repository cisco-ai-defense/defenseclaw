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
	"encoding/json"
	"net/http"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// TestAgentHookTrustedActionShellShapes pins the two shell shapes that parsed
// only partially, so command rules could not prove a trusted action and a
// CRITICAL finding stayed an allowed candidate: OmniGent's sys_os_shell tool
// name and OpenHands' TerminalAction fields.
func TestAgentHookTrustedActionShellShapes(t *testing.T) {
	const command = `{"command":"echo DCE2E-BLOCK-MARKER > /tmp/dce2e-blocked.txt"}`
	for _, tc := range []struct {
		name, connector, tool, args string
	}{
		{"omnigent-sys-os-shell", "omnigent", "sys_os_shell", command},
		{"openhands-terminal-action", "openhands", "terminal",
			`{"command":"echo DCE2E-BLOCK-MARKER > /tmp/dce2e-blocked.txt","is_input":false,"timeout":null,"reset":false,"kind":"TerminalAction"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := actionfacts.Analyze(actionfacts.Input{Tool: tc.tool, Args: json.RawMessage(tc.args)})
			if raw.Parse.Status == actionfacts.StatusComplete {
				t.Skip("the raw shape now parses completely upstream; the mapping is redundant")
			}
			mapped := actionfacts.Analyze(actionfacts.Input{
				Tool: agentHookTrustedActionTool(tc.connector, tc.tool, "linux"),
				Args: agentHookTrustedActionArgs(tc.connector, tc.tool, json.RawMessage(tc.args)),
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
	if got := agentHookTrustedActionArgs("hermes", "terminal", args); string(got) != string(args) {
		t.Errorf("hermes terminal args = %s, want passthrough", got)
	}
	if got := agentHookTrustedActionArgs("openhands", "terminal", json.RawMessage(`{"command":"ls","is_input":true}`)); string(got) != `{"command":"ls","is_input":true}` {
		t.Errorf("input to a running process was projected: %s", got)
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
	f := newSandboxIngressFixture(t, func(c *SandboxIngressConfig) {
		c.OnHookDecision = func(d SandboxHookDecision) {
			mu.Lock()
			defer mu.Unlock()
			decisions = append(decisions, d)
		}
	})
	const command = "echo DCE2E-BLOCK-MARKER > /tmp/dce2e-blocked.txt"
	want := "Blocked by DefenseClaw rule E2E-SANDBOX-MARKER: E2E sandbox marker command. " + sandboxDefaultRemediation
	for _, tc := range []struct {
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
			body:    `{"toolCall":{"name":"run_command","args":{"CommandLine":"` + command + `","Cwd":"/work/app"}}}`,
			output: func(t *testing.T, resp map[string]interface{}) {
				out, _ := resp["hook_output"].(map[string]interface{})
				if out["decision"] != "deny" {
					t.Fatalf("antigravity hook_output = %v", out)
				}
			},
		},
		{
			connector: "omnigent", version: "0.13.0", contract: "omnigent-custom-policy-v1", path: "/api/v1/omnigent/hook", tool: "sys_os_shell",
			body: `{"hook_event_name":"PreToolUse","omnigent_event_type":"tool_call","agent_name":"OmniGent","agent_type":"omnigent",` +
				`"omnigent_actor_client_id":"","model":"mock-model","omnigent_session_id_status":"unavailable_in_v0.7_policy_event",` +
				`"tool_name":"sys_os_shell","tool_input":{"command":"` + command + `"}}`,
		},
	} {
		t.Run(tc.connector, func(t *testing.T) {
			_, token, err := f.store.Mint(sandboxauth.Spec{
				SandboxName: "dc-" + tc.connector + "-app", Connector: tc.connector,
				AgentVersion: tc.version, HookContractID: tc.contract, PolicyProfile: "open",
				Workdir:  sandboxauth.Workdir{Mode: sandboxauth.WorkdirCopy},
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
