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

package connector

import (
	"encoding/json"
	"strings"
	"testing"
)

// sandboxNativeBlockText returns what a sandbox hook shows the agent in its
// own block output for a refused call, taken from the channel the agent reads
// and never from the log line on stderr: the user_message and agent_message of
// Cursor, the plain stdout of Devin, the block objects of Hermes and
// Antigravity (decoded, so a bad escape fails), and for the hooks whose exit 2
// is the block (Claude Code, Codex, Copilot, Kiro) the stderr text shown.
func sandboxNativeBlockText(connector string, run sandboxHookRun) []string {
	obj := lastJSON(run)
	str := func(key string) string {
		v, _ := obj[key].(string)
		return v
	}
	switch connector {
	case "cursor":
		return []string{str("user_message"), str("agent_message")}
	case "devin":
		return []string{run.stdout}
	case "hermes":
		return []string{str("message")}
	case "antigravity":
		return []string{str("reason")}
	default:
		return []string{run.stderr}
	}
}

// Every sandbox hook that blocks a call the gateway refused 429 shows the
// gateway's readable cause, never a bare status or an outage text. The cause
// is the message the gateway wrote for the limit that refused (this sandbox,
// its waiting requests, the user's sandboxes together, the gateway as a whole):
// the hook relays it and invents none (rel-1-0-6 GAP-0490).
func TestEverySandboxHookShowsTheGatewayRateRefusalCause(t *testing.T) {
	// A quote and a backslash in the message must not break the JSON a hook
	// prints for its agent.
	const marker = `this one sandbox is over its "configured" hook rate \\ of 3 a second`
	bodyJSON, err := json.Marshal(map[string]string{
		"error": "rate_limited", "reason": "sandbox_rate_limited", "message": marker, "retry_after_seconds": "1",
	})
	if err != nil {
		t.Fatal(err)
	}
	body := string(bodyJSON)
	for _, tc := range sandboxHookCases() {
		if !tc.lifecycle {
			continue
		}
		t.Run(tc.connector, func(t *testing.T) {
			h := newSandboxHookHarness(t, tc.provider, tc.version)
			env := map[string]string{SandboxTokenEnv: "sandbox-token", "CLAUDE_TOOL_NAME": "Bash"}
			run := h.run(t, SandboxHookDir+"/"+tc.script, tc.args, tc.stdin, env, []string{"429|" + body})
			text := run.stdout + run.stderr
			if !tc.blocked(run) {
				t.Fatalf("a 429 was allowed: exit=%d stdout=%q stderr=%q", run.exitCode, run.stdout, run.stderr)
			}
			if !strings.Contains(text, "over its") || !strings.Contains(text, "configured") {
				t.Errorf("the 429 did not show the gateway's cause: stdout=%q stderr=%q", run.stdout, run.stderr)
			}
			if strings.Contains(text, "gateway unreachable") {
				t.Errorf("a 429 was reported as an outage: %q", text)
			}
			// A hook that prints JSON for its agent still prints valid JSON.
			if strings.HasPrefix(strings.TrimSpace(run.stdout), "{") && lastJSON(run) == nil {
				t.Errorf("the 429 broke the hook's JSON output: %q", run.stdout)
			}
		})
	}
}

// The cause the gateway states reaches the agent in each hook own block
// output, not only in the stderr log line, and the output stays valid JSON for
// the hooks that print JSON, with a quote and a backslash in the message.
func TestEverySandboxHookNativeBlockOutputCarriesTheGatewayCause(t *testing.T) {
	const marker = `this one sandbox is over its "configured" hook rate \\ of 3 a second`
	bodyJSON, err := json.Marshal(map[string]string{
		"error": "rate_limited", "reason": "sandbox_rate_limited", "message": marker, "retry_after_seconds": "1",
	})
	if err != nil {
		t.Fatal(err)
	}
	body := string(bodyJSON)
	for _, tc := range sandboxHookCases() {
		if !tc.lifecycle {
			continue
		}
		t.Run(tc.connector, func(t *testing.T) {
			h := newSandboxHookHarness(t, tc.provider, tc.version)
			env := map[string]string{SandboxTokenEnv: "sandbox-token", "CLAUDE_TOOL_NAME": "Bash"}
			run := h.run(t, SandboxHookDir+"/"+tc.script, tc.args, tc.stdin, env, []string{"429|" + body})
			if !tc.blocked(run) {
				t.Fatalf("a 429 was allowed: exit=%d stdout=%q stderr=%q", run.exitCode, run.stdout, run.stderr)
			}
			for _, text := range sandboxNativeBlockText(tc.connector, run) {
				if !strings.Contains(text, marker) {
					t.Errorf("the block output the agent reads lacks the gateway cause %q: %q (stdout=%q stderr=%q)", marker, text, run.stdout, run.stderr)
				}
				if strings.Contains(text, "failed closed") {
					t.Errorf("the block output is the generic text: %q", text)
				}
			}
		})
	}
}

// The benign twin: the same hooks allow an ordinary call the gateway answered.
func TestEverySandboxHookStillAllowsAnAnsweredCall(t *testing.T) {
	for _, tc := range sandboxHookCases() {
		if !tc.lifecycle {
			continue
		}
		t.Run(tc.connector, func(t *testing.T) {
			h := newSandboxHookHarness(t, tc.provider, tc.version)
			env := map[string]string{SandboxTokenEnv: "sandbox-token", "CLAUDE_TOOL_NAME": "Bash"}
			run := h.run(t, SandboxHookDir+"/"+tc.script, tc.args, tc.stdin, env, []string{allowResponse, allowResponse})
			if run.exitCode != 0 || tc.blocked(run) {
				t.Fatalf("an answered call was blocked: exit=%d stdout=%q stderr=%q", run.exitCode, run.stdout, run.stderr)
			}
		})
	}
}

// The Antigravity sandbox deny keeps the sentence that says the request was
// refused with its status, and adds the limit the gateway named when it named
// one. A 429 that names no limit (a bare error body or no body) keeps the
// sentence alone.
func TestSandboxAntigravityRateRefusalSaysWhyAndNamesTheLimit(t *testing.T) {
	const said = "DefenseClaw hook request was refused (HTTP 429), so the tool call is blocked."
	agy := newSandboxHookHarness(t, NewAntigravityConnector(), "1.2.12")
	token := map[string]string{SandboxTokenEnv: "tok"}
	for _, tc := range []struct{ name, body, want string }{
		{"names the limit", `{"error":"rate_limited","message":"this sandbox is over its \"hook\" rate of 25 a second"}`,
			said[:len(said)-1] + `: this sandbox is over its "hook" rate of 25 a second`},
		{"bare error body", `{"error":"slow down"}`, said},
		{"no body", ``, said},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := agy.run(t, SandboxHookDir+"/antigravity-hook.sh", []string{"PreToolUse"}, antigravityPreToolUse, token, []string{"429|" + tc.body})
			got := lastJSON(run)
			if run.exitCode != 0 || got["decision"] != "deny" || got["reason"] != tc.want {
				t.Fatalf("exit %d stdout %q, want a deny with reason %q; stderr=%s", run.exitCode, run.stdout, tc.want, run.stderr)
			}
		})
	}
}
