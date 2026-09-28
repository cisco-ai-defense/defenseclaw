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

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// sandboxShellCallMistyped gives a listed argument of each shell call a
// value of another JSON type, so the connector's projection refuses the
// call. Calls whose tool takes no argument but the command have none.
func sandboxShellCallMistyped(tc workdirShellCall) (string, bool) {
	if strings.Contains(tc.body, `"{DIR}"`) {
		return strings.ReplaceAll(tc.body, `"{DIR}"`, `7`), true
	}
	for _, swap := range [][2]string{
		{`"description":"write marker"`, `"description":["write marker"]`},
		{`"timeout":120000`, `"timeout":"120000"`},
		{`"timeout":null`, `"timeout":"soon"`},
	} {
		if strings.Contains(tc.body, swap[0]) {
			return strings.Replace(tc.body, swap[0], swap[1], 1), true
		}
	}
	return "", false
}

// TestSandboxShellCallsWithOtherArgumentsAreJudged pins that the shell tool
// call of every sandboxed harness still reaches the command rules when it
// carries an argument the connector's projection does not list, or a
// listed one with a value of another type. Either left the trusted-action
// parse partial, so the CRITICAL marker rule's match was only a candidate
// and the verdict was allow: one extra argument turned a block into an
// allow. The command is now also judged on its own, and the block carries
// the rule's plain reason.
func TestSandboxShellCallsWithOtherArgumentsAreJudged(t *testing.T) {
	installSandboxMarkerRules(t)
	f := newSandboxIngressFixture(t)
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(project, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	want := "Blocked by DefenseClaw rule E2E-SANDBOX-MARKER: E2E sandbox marker command. " + sandboxDefaultRemediation
	marker := `"` + workdirMarkerCommand + `"`
	for i, tc := range workdirShellCalls() {
		base := strings.ReplaceAll(tc.body, "{DIR}", "/work/app/sub")
		bodies := map[string]string{
			"unlisted":      strings.Replace(base, marker, marker+`,"dc_unlisted_arg":"x"`, 1),
			"unlisted-null": strings.Replace(base, marker, marker+`,"dc_unlisted_arg":null`, 1),
		}
		if mistyped, ok := sandboxShellCallMistyped(tc); ok {
			bodies["mistyped"] = strings.ReplaceAll(mistyped, "{DIR}", "/work/app/sub")
		}
		for variant, body := range bodies {
			t.Run(tc.name+"/"+variant, func(t *testing.T) {
				if body == base {
					t.Fatal("the variant did not change the call")
				}
				_, token, err := f.store.Mint(sandboxauth.Spec{
					SandboxName: "dc-" + tc.connector + "-arg-" + strconv.Itoa(i) + "-" + variant, Connector: tc.connector,
					AgentVersion: tc.version, HookContractID: tc.contract, PolicyProfile: "open",
					Workdir: sandboxauth.Workdir{Mode: sandboxauth.WorkdirMount,
						Mounts: []sandboxauth.Mount{{SandboxPath: "/work/app", HostPath: project}}},
					HostUser: sandboxauth.HostUser{UID: "1000", Name: "dev"},
				})
				if err != nil {
					t.Fatal(err)
				}
				rec := f.do(t, http.MethodPost, tc.path, token, body, tc.headers...)
				if rec.Code != http.StatusOK {
					t.Fatalf("hook: %d %s", rec.Code, rec.Body.String())
				}
				var resp map[string]interface{}
				if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatal(err)
				}
				if resp["action"] != "block" || resp["raw_action"] != "block" {
					t.Fatalf("verdict = %s", rec.Body.String())
				}
				// Claude Code and Codex render their own reasons.
				if tc.connector != "claudecode" && tc.connector != "codex" && resp["reason"] != want {
					t.Fatalf("reason = %v, want %q", resp["reason"], want)
				}
			})
		}
	}
}

// TestSandboxShellCommandOnlyAddsVerdicts pins that judging a sandbox shell
// call's command alone decides nothing the command does not: a harmless
// command with an extra argument stays allowed, and a marker that appears
// only in a dropped argument, not in the command, is not a block.
func TestSandboxShellCommandOnlyAddsVerdicts(t *testing.T) {
	installSandboxMarkerRules(t)
	f := newSandboxIngressFixture(t)
	for i, args := range []string{
		`{"command":"ls -la","dc_unlisted_arg":"x"}`,
		`{"command":"ls -la","workdir":7}`,
		`{"command":"ls -la","workdir":"/work/app","dc_unlisted_arg":"DCE2E-BLOCK-MARKER"}`,
	} {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			_, token, err := f.store.Mint(sandboxauth.Spec{
				SandboxName: "dc-opencode-harmless-" + strconv.Itoa(i), Connector: "opencode",
				AgentVersion: "1.18.10", HookContractID: "opencode-hooks-v1", PolicyProfile: "open",
				Workdir:  sandboxauth.Workdir{Mode: sandboxauth.WorkdirMount, Mounts: []sandboxauth.Mount{{SandboxPath: "/work/app", HostPath: f.project}}},
				HostUser: sandboxauth.HostUser{UID: "1000", Name: "dev"},
			})
			if err != nil {
				t.Fatal(err)
			}
			body := `{"hook_event_name":"tool.execute.before","tool_name":"bash","tool_input":` + args +
				`,"session_id":"s1","turn_id":"m1","tool_call_id":"c1","agent_name":"build","cwd":"/work/app","load_heartbeat":true,` +
				`"arguments_authoritative":true,"mcp_identity_status":"not_mcp"}`
			rec := f.do(t, http.MethodPost, "/api/v1/opencode/hook", token, body)
			if rec.Code != http.StatusOK {
				t.Fatalf("hook: %d %s", rec.Code, rec.Body.String())
			}
			var resp map[string]interface{}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			if resp["action"] == "block" || resp["raw_action"] == "block" {
				t.Fatalf("verdict = %s", rec.Body.String())
			}
		})
	}
}

func TestSandboxShellCommandScope(t *testing.T) {
	args := json.RawMessage(`{"command":"ls","dc_unlisted_arg":1}`)
	if command, tool := sandboxShellCommand(context.Background(), "opencode", "tool.execute.before", "bash", "bash", args); command != nil || tool != "" {
		t.Fatalf("host request = %s, %q; want none", command, tool)
	}
	ctx := sandboxauth.WithRequest(context.Background(), sandboxTestBinding("opencode"), nil)
	if command, tool := sandboxShellCommand(ctx, "opencode", "tool.execute.before", "bash", "bash", args); string(command) != `{"command":"ls"}` || tool != "bash" {
		t.Fatalf("sandbox request = %s, %q", command, tool)
	}
	// Another connector's binding, and a tool that is not a shell.
	if command, _ := sandboxShellCommand(ctx, "hermes", "pre_tool_call", "terminal", "terminal", args); command != nil {
		t.Fatalf("other connector's binding = %s", command)
	}
	if command, _ := sandboxShellCommand(ctx, "opencode", "tool.execute.before", "read", "read", args); command != nil {
		t.Fatalf("read tool = %s", command)
	}
	// Cursor's beforeShellExecution payload is the call, judged as a shell.
	cursor := sandboxauth.WithRequest(context.Background(), sandboxTestBinding("cursor"), nil)
	if command, tool := sandboxShellCommand(cursor, "cursor", "beforeShellExecution", "tool", "tool",
		json.RawMessage(`{"command":"ls","cwd":7}`)); string(command) != `{"command":"ls"}` || tool != "shell" {
		t.Fatalf("cursor event = %s, %q", command, tool)
	}
}

func TestMergeSandboxShellCommandVerdict(t *testing.T) {
	candidate := RuleFinding{RuleID: "E2E-SANDBOX-MARKER", Title: "E2E sandbox marker command", Severity: "CRITICAL",
		Confidence: 0.99, enforcement: findingEnforcementDetectionOnly}
	proven := candidate
	proven.enforcement = findingEnforcementAllowed
	allow := &ToolInspectVerdict{Action: "allow", Severity: "CRITICAL", Reason: "matched: E2E-SANDBOX-MARKER:E2E sandbox marker command",
		Findings: []string{"E2E-SANDBOX-MARKER:E2E sandbox marker command"}, DetailedFindings: []RuleFinding{candidate}}

	got := mergeSandboxShellCommandVerdict(nil, "opencode", allow, []RuleFinding{proven})
	if got == allow || got.Action != "block" || got.Severity != "CRITICAL" ||
		len(got.DetailedFindings) != 1 || !got.DetailedFindings[0].contributesToEnforcement() ||
		len(got.Findings) != 1 || got.Reason != "matched: E2E-SANDBOX-MARKER:E2E sandbox marker command" {
		t.Fatalf("merged = %+v", got)
	}
	if allow.Action != "allow" || allow.DetailedFindings[0].contributesToEnforcement() {
		t.Fatalf("the call's verdict changed: %+v", allow)
	}
	// A candidate alone, or no finding, adds nothing.
	for _, findings := range [][]RuleFinding{{candidate}, nil} {
		if got := mergeSandboxShellCommandVerdict(nil, "opencode", allow, findings); got != allow {
			t.Fatalf("merged %+v = %+v", findings, got)
		}
	}
	// Never lifts a verdict: a block stays a block whatever the command.
	block := &ToolInspectVerdict{Action: "block", Severity: "HIGH", Findings: []string{"STATIC-BLOCK"}}
	if got := mergeSandboxShellCommandVerdict(nil, "opencode", block, nil); got != block {
		t.Fatalf("block = %+v", got)
	}
	// A new rule is added next to the call's findings and raises severity.
	low := &ToolInspectVerdict{Action: "allow", Severity: "LOW", Findings: []string{"OTHER:Other"},
		DetailedFindings: []RuleFinding{{RuleID: "OTHER", Title: "Other", Severity: "LOW"}}}
	got = mergeSandboxShellCommandVerdict(nil, "opencode", low, []RuleFinding{proven})
	if got.Action != "block" || got.Severity != "CRITICAL" || got.Confidence != 0.99 ||
		len(got.DetailedFindings) != 2 || len(got.Findings) != 2 {
		t.Fatalf("merged = %+v", got)
	}
}
