// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// A per-user Copilot CLI hook bound to no reviewed event cannot tell
// preToolUse from permissionRequest: in fail mode closed (or strict
// availability) it writes both of Copilot's denies and says how to register
// the hook again, like the standalone hook; in fail mode open the call runs.
// The gateway is never asked.
func TestPerUserCopilotHookRefusesAnUnboundEvent(t *testing.T) {
	for _, event := range []string{"", "futureEvent", "PreToolUse"} {
		for _, mode := range []string{"closed", "strict", "open"} {
			t.Run(event+"/"+mode, func(t *testing.T) {
				rt := ok(`{"action":"allow"}`)
				result := run(t, "copilot", rt, func(opts *Options) {
					opts.Event = event
					opts.FailMode = "closed"
					switch mode {
					case "strict":
						opts.FailMode = "open"
						opts.StrictAvailability = true
					case "open":
						opts.FailMode = "open"
					}
				})
				if rt.requests != 0 {
					t.Fatalf("unbound event %q reached the gateway", event)
				}
				if mode == "open" {
					if result.code != 0 || result.stdout != "" {
						t.Fatalf("open: code=%d stdout=%q, want the fail-open result", result.code, result.stdout)
					}
					return
				}
				if result.code != 0 || !strings.Contains(result.stdout, `"permissionDecision":"deny"`) ||
					!strings.Contains(result.stdout, `"behavior":"deny"`) || !strings.Contains(result.stdout, "defenseclaw setup copilot") ||
					strings.Contains(result.stdout, "administrator") {
					t.Fatalf("code=%d stdout=%q stderr=%q, want both denies with the per-user next step",
						result.code, result.stdout, result.stderr)
				}
			})
		}
	}
}

// A closed per-user Copilot CLI or Antigravity hook accepts a confirmation
// only with the agent's native ask (Antigravity: force_ask) and a block only
// with its native deny, as
// copilot-hook.sh and antigravity-hook.sh check; anything else is no verdict
// and is denied. A real ask passes through, and fail mode open lets an
// unusable answer run.
func TestPerUserHookDeniesAnAnswerWithoutTheNativeDecision(t *testing.T) {
	for _, tc := range []struct {
		name, connector, event, body, mode, want string
	}{
		{"copilot preToolUse confirm", "copilot", "preToolUse", `{"action":"confirm"}`, "closed", `"permissionDecision":"deny"`},
		{"copilot preToolUse confirm allow", "copilot", "preToolUse",
			`{"action":"confirm","hook_output":{"permissionDecision":"allow"}}`, "closed", `"permissionDecision":"deny"`},
		{"copilot permissionRequest confirm", "copilot", "permissionRequest", `{"action":"confirm"}`, "closed", `"behavior":"deny"`},
		{"copilot preToolUse ask", "copilot", "preToolUse",
			`{"action":"confirm","hook_output":{"permissionDecision":"ask","permissionDecisionReason":"check"}}`, "closed", `"permissionDecision":"ask"`},
		{"antigravity confirm", "antigravity", "PreToolUse", `{"action":"confirm"}`, "closed", `"decision":"deny"`},
		{"antigravity confirm allow", "antigravity", "PreToolUse",
			`{"action":"confirm","hook_output":{"decision":"allow"}}`, "closed", `"decision":"deny"`},
		{"antigravity block", "antigravity", "PreToolUse", `{"action":"block"}`, "closed", `"decision":"deny"`},
		// GAP-0405: a plain ask honors a cached Always Allow grant, so only
		// force_ask is Antigravity's confirmation.
		{"antigravity plain ask", "antigravity", "PreToolUse",
			`{"action":"confirm","hook_output":{"decision":"ask","reason":"check"}}`, "closed", `"decision":"deny"`},
		{"antigravity force_ask", "antigravity", "PreToolUse",
			`{"action":"confirm","hook_output":{"decision":"force_ask","reason":"check"}}`, "closed", `"decision":"force_ask"`},
		{"antigravity confirm open", "antigravity", "PreToolUse", `{"action":"confirm"}`, "open", `"decision":"allow"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := run(t, tc.connector, ok(tc.body), func(opts *Options) {
				opts.Event = tc.event
				opts.FailMode = tc.mode
			})
			if result.code != 0 || !strings.Contains(result.stdout, tc.want) || strings.Count(result.stdout, "\n") != 1 {
				t.Fatalf("code=%d stdout=%q stderr=%q, want one answer with %s", result.code, result.stdout, result.stderr, tc.want)
			}
		})
	}
}

// Review round 3: strict availability closes a per-user hook rendered open
// (an explicit open Windows sidecar) for the answer checks too. The checks
// read the raw open mode, so a block or confirm without the native deny, or
// an answer with no valid action, let the call run.
func TestStrictAvailabilityClosesAnOpenPerUserHookAnswer(t *testing.T) {
	for _, tc := range []struct {
		name, connector, event, body, want string
	}{
		{"copilot preToolUse block", "copilot", "preToolUse", `{"action":"block"}`, `"permissionDecision":"deny"`},
		{"copilot preToolUse block allow", "copilot", "preToolUse",
			`{"action":"block","hook_output":{"permissionDecision":"allow"}}`, `"permissionDecision":"deny"`},
		{"copilot permissionRequest confirm", "copilot", "permissionRequest", `{"action":"confirm"}`, `"behavior":"deny"`},
		{"copilot preToolUse invalid action", "copilot", "preToolUse", `{"action":"maybe"}`, `"permissionDecision":"deny"`},
		{"antigravity block", "antigravity", "PreToolUse", `{"action":"block"}`, `"decision":"deny"`},
		{"antigravity confirm allow", "antigravity", "PreToolUse",
			`{"action":"confirm","hook_output":{"decision":"allow"}}`, `"decision":"deny"`},
		{"antigravity invalid action", "antigravity", "PreToolUse", `{"action":"maybe"}`, `"decision":"deny"`},
		{"antigravity not json", "antigravity", "PreToolUse", `not json`, `"decision":"deny"`},
	} {
		for _, strict := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/strict=%v", tc.name, strict), func(t *testing.T) {
				result := run(t, tc.connector, ok(tc.body), func(opts *Options) {
					opts.Event = tc.event
					opts.FailMode = "open"
					opts.StrictAvailability = strict
				})
				if !strict {
					// Fail mode open without strict availability lets it run.
					if strings.Contains(result.stdout, "deny") {
						t.Fatalf("open: stdout=%q, want no deny", result.stdout)
					}
					return
				}
				if result.code != 0 || !strings.Contains(result.stdout, tc.want) || strings.Count(result.stdout, "\n") != 1 {
					t.Fatalf("code=%d stdout=%q stderr=%q, want one answer with %s", result.code, result.stdout, result.stderr, tc.want)
				}
			})
		}
	}
}

// Review round 2: a closed Copilot CLI hook whose registration lost its event
// is refused before the early exits. An unavailable home, oversized input or
// an invalid managed runtime answered it as an event that cannot block, so
// Copilot ran the call.
func TestClosedCopilotHookRefusesAnUnboundEventBeforeEarlyExits(t *testing.T) {
	for _, event := range []string{"", "futureEvent"} {
		for _, path := range []string{"home missing", "oversized", "managed runtime"} {
			t.Run(event+"/"+path, func(t *testing.T) {
				rt := ok(`{"action":"allow"}`)
				result := run(t, "copilot", rt, func(opts *Options) {
					opts.Event = event
					opts.FailMode = "closed"
					switch path {
					case "home missing":
						opts.Home = filepath.Join(opts.Home, "missing")
					case "oversized":
						opts.MaxBody = 2
					case "managed runtime":
						managedCodex(opts)
						opts.ManagedRuntimeFailure = "enterprise_managed_runtime_invalid"
					}
				})
				want := "defenseclaw setup copilot"
				if path == "managed runtime" {
					want = "administrator"
				}
				if rt.requests != 0 || result.code != 0 || !strings.Contains(result.stdout, `"permissionDecision":"deny"`) ||
					!strings.Contains(result.stdout, `"behavior":"deny"`) || !strings.Contains(result.stdout, want) {
					t.Fatalf("code=%d requests=%d stdout=%q stderr=%q, want both denies naming %q",
						result.code, rt.requests, result.stdout, result.stderr, want)
				}
			})
		}
	}
	open := run(t, "copilot", ok(`{"action":"allow"}`), func(opts *Options) {
		opts.Event = ""
		opts.FailMode = "open"
		opts.Home = filepath.Join(opts.Home, "missing")
	})
	if strings.Contains(open.stdout, "deny") {
		t.Fatalf("fail mode open keeps Copilot's fail-open result: stdout=%q", open.stdout)
	}
}

// Review round 2: an Antigravity hook whose registration lost its event
// denies a tool call in fail mode closed, on every failure path, and keeps
// the neutral answer for any other input (Stop reads the same decision
// field) and in fail mode open. The gateway, which requires the event, is
// never asked.
func TestClosedAntigravityHookDeniesAnUnboundToolCall(t *testing.T) {
	toolCall := `{"toolCall":{"name":"run_command","args":{"CommandLine":"echo ok"}}}`
	stop := `{"conversationId":"c1","terminationReason":"done"}`
	for _, tc := range []struct {
		name, event, mode, input, path, want string
		deny                                 bool
	}{
		{name: "unbound", input: toolCall, mode: "closed", deny: true, want: "defenseclaw setup antigravity"},
		{name: "unknown event", event: "FutureEvent", input: toolCall, mode: "closed", deny: true, want: "defenseclaw setup antigravity"},
		{name: "snake case tool call", input: `{"tool_call":{"name":"x","args":{}}}`, mode: "closed", deny: true, want: "defenseclaw setup antigravity"},
		{name: "strict", input: toolCall, mode: "strict", deny: true, want: "defenseclaw setup antigravity"},
		{name: "home missing", input: toolCall, mode: "closed", path: "home missing", deny: true, want: "defenseclaw setup antigravity"},
		{name: "oversized", input: toolCall, mode: "closed", path: "oversized", deny: true, want: "defenseclaw setup antigravity"},
		{name: "managed runtime", input: toolCall, mode: "closed", path: "managed runtime", deny: true, want: "administrator"},
		{name: "stop input", input: stop, mode: "closed"},
		{name: "stop input home missing", input: stop, mode: "closed", path: "home missing"},
		{name: "invocation input", input: `{"conversationId":"c1","invocationNum":2,"initialNumSteps":0}`, mode: "closed"},
		{name: "open", input: toolCall, mode: "open"},
		// Review round 3: only an input that is clearly another event keeps
		// the neutral answer; one that may be a tool call is denied.
		{name: "no tool call", input: `{"conversationId":"c1"}`, mode: "closed", deny: true, want: "defenseclaw setup antigravity"},
		{name: "null tool call", input: `{"toolCall":null}`, mode: "closed", deny: true, want: "defenseclaw setup antigravity"},
		{name: "string tool call", input: `{"toolCall":"run_command"}`, mode: "closed", deny: true, want: "defenseclaw setup antigravity"},
		{name: "tool step", input: `{"stepIdx":3,"terminationReason":"done"}`, mode: "closed", deny: true, want: "defenseclaw setup antigravity"},
		{name: "not json", input: `run_command`, mode: "closed", deny: true, want: "defenseclaw setup antigravity"},
		{name: "empty", input: ``, mode: "closed", deny: true, want: "defenseclaw setup antigravity"},
		{name: "array", input: `[{"terminationReason":"done"}]`, mode: "closed", deny: true, want: "defenseclaw setup antigravity"},
		{name: "oversized stop", input: stop, mode: "closed", path: "oversized", deny: true, want: "defenseclaw setup antigravity"},
		{name: "managed runtime no tool call", input: `{"conversationId":"c1"}`, mode: "closed", path: "managed runtime", deny: true, want: "administrator"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := ok(`{"action":"allow"}`)
			result := run(t, "antigravity", rt, func(opts *Options) {
				opts.Event = tc.event
				opts.FailMode = tc.mode
				if tc.mode == "strict" {
					opts.FailMode = "open"
					opts.StrictAvailability = true
				}
				opts.Stdin = strings.NewReader(tc.input)
				switch tc.path {
				case "home missing":
					opts.Home = filepath.Join(opts.Home, "missing")
				case "oversized":
					opts.MaxBody = 16
				case "managed runtime":
					managedCodex(opts)
					opts.ManagedRuntimeFailure = "enterprise_managed_runtime_invalid"
				}
			})
			if rt.requests != 0 || result.code != 0 {
				t.Fatalf("code=%d requests=%d stderr=%q, want exit 0 and no gateway request", result.code, rt.requests, result.stderr)
			}
			denied := strings.Contains(result.stdout, `"decision":"deny"`)
			if denied != tc.deny || (tc.deny && !strings.Contains(result.stdout, tc.want)) {
				t.Fatalf("stdout=%q stderr=%q, want deny=%v naming %q", result.stdout, result.stderr, tc.deny, tc.want)
			}
		})
	}
}
