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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// lastHookFailure is the last line of the hook-failure log under home.
func lastHookFailure(t *testing.T, home string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(home, "logs", "hook-failures.jsonl"))
	if err != nil {
		t.Fatalf("read hook-failures.jsonl: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var entry map[string]string
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &entry); err != nil {
		t.Fatalf("decode %q: %v", lines[len(lines)-1], err)
	}
	return entry
}

func hermesBlockMessage(t *testing.T, stdout string) string {
	t.Helper()
	var body map[string]string
	if err := json.Unmarshal(bytes.TrimSpace([]byte(stdout)), &body); err != nil || body["action"] != "block" {
		t.Fatalf("stdout = %q, want a Hermes block directive", stdout)
	}
	return body["message"]
}

// rel-1-0-2 GAP-0423: on a managed deployment outside Secure Client the
// native Hermes hook (Windows) blocks a tool call DefenseClaw cannot check,
// in every failure layer, says why, and logs the call as failed closed.
func TestManagedHermesToolCallBlocksWhenDefenseClawCannotCheck(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		rt         *stubRT
		mutate     func(*Options)
	}{
		{name: "gateway unreachable", want: "the DefenseClaw gateway is not available",
			rt: &stubRT{err: errors.New("connection refused")}},
		{name: "gateway 5xx", want: "the DefenseClaw gateway is not available",
			rt: &stubRT{status: 503, body: "unavailable"}},
		{name: "gateway refused", want: "returned an answer DefenseClaw could not use",
			rt: &stubRT{status: 401, body: "unauthorized"}},
		{name: "malformed answer", want: "returned an answer DefenseClaw could not use", rt: ok("not-json")},
		{name: "block without directive", want: "returned an answer DefenseClaw could not use",
			rt: ok(`{"action":"block","reason":"policy"}`)},
		{name: "oversized", want: "too large for DefenseClaw to inspect", rt: ok(`{"action":"allow"}`),
			mutate: func(o *Options) { o.MaxBody = 2 }},
		{name: "missing token", want: "the DefenseClaw gateway is not available", rt: ok(`{"action":"allow"}`),
			mutate: func(o *Options) {
				o.Token = ""
				o.HookDir = filepath.Join(o.Home, "no-token")
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var home string
			result := run(t, "hermes", tc.rt, func(o *Options) {
				o.Event = "pre_tool_call"
				o.FailMode = "closed"
				o.ManagedEnterprise = true
				o.ExplainUnenrolledAccount = true
				o.Stdin = strings.NewReader(`{"hook_event_name":"pre_tool_call","tool_name":"terminal"}`)
				if tc.mutate != nil {
					tc.mutate(o)
				}
				home = o.Home
				o.FailureLogHome = userLogHome(o.Home)
			})
			message := hermesBlockMessage(t, result.stdout)
			if result.code != 0 || !strings.HasPrefix(message, "DefenseClaw blocked this tool call: ") ||
				!strings.Contains(message, tc.want) {
				t.Fatalf("code %d, message %q, want a tool-call block naming %q (stderr %q)", result.code, message, tc.want, result.stderr)
			}
			if got := lastHookFailure(t, home)["fail_mode"]; got != "closed" {
				t.Fatalf("logged fail_mode = %q, want closed", got)
			}
		})
	}
}

// The Windows standalone hook resolves a stopped gateway service before it
// sends anything (ManagedRuntimeFailure); Hermes then says the service is
// not running, and an unenrolled account is told so.
func TestManagedHermesNativeRuntimeFailureNamesTheCause(t *testing.T) {
	for reason, want := range map[string]string{
		managedGatewayNotRunningReason: "the DefenseClaw gateway service is not running on this computer",
		managedSIDUnregisteredReason:   "this account is not enrolled yet",
	} {
		var stdout, stderr bytes.Buffer
		code := Run(context.Background(), Options{
			Connector:                "hermes",
			Event:                    "pre_tool_call",
			ManagedEnterprise:        true,
			ExplainUnenrolledAccount: true,
			ManagedRuntimeFailure:    reason,
			Home:                     t.TempDir(),
			Stdin:                    strings.NewReader(`{"hook_event_name":"pre_tool_call"}`),
			Stdout:                   &stdout,
			Stderr:                   &stderr,
		})
		if message := hermesBlockMessage(t, stdout.String()); code != 0 || !strings.Contains(message, want) {
			t.Fatalf("%s: code %d, message %q, want %q", reason, code, message, want)
		}
	}
}

// Secure Client Hermes hooks, a per-user hook whose fail mode is explicitly
// open, and Hermes events that cannot block keep the neutral result; the log
// says the call ran fail-open (rel-1-0-2 GAP-0446 item 5: a closed
// configured mode was logged before). A per-user hook in fail mode closed or
// with none set blocks (TestPerUserHermesToolCallFailsClosedUnlessOpen).
func TestHermesNeutralResultOutsideManagedToolCalls(t *testing.T) {
	for name, mutate := range map[string]func(*Options){
		"per-user open": func(o *Options) {
			o.FailMode = "open"
			o.StrictAvailability = false
		},
		"secure client": func(o *Options) {
			o.ManagedEnterprise = true
			o.SecureClient = true
		},
		"managed pre_llm_call": func(o *Options) {
			o.ManagedEnterprise = true
			o.ExplainUnenrolledAccount = true
			o.Event = "pre_llm_call"
		},
	} {
		t.Run(name, func(t *testing.T) {
			var home string
			result := run(t, "hermes", &stubRT{err: errors.New("connection refused")}, func(o *Options) {
				o.Event = "pre_tool_call"
				o.FailMode = "closed"
				o.StrictAvailability = true
				mutate(o)
				home = o.Home
				o.FailureLogHome = userLogHome(o.Home)
			})
			if result.code != 0 || strings.Contains(result.stdout, `"block"`) {
				t.Fatalf("code %d, stdout %q, want the neutral result", result.code, result.stdout)
			}
			if got := lastHookFailure(t, home)["fail_mode"]; got != "open" {
				t.Fatalf("logged fail_mode = %q, want open", got)
			}
		})
	}
}

// rel-1-0-3 B-20 review item 1: a managed Hermes tool call blocks on a
// successful gateway answer that carries no usable verdict (no action, an
// unknown one, a block without its directive or with one that does not
// block). The allow and alert answers of observe mode still run.
func TestManagedHermesUnusableSuccessfulAnswerBlocks(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		blocks     bool
	}{
		{"missing action", `{}`, true},
		{"empty action", `{"action":""}`, true},
		{"unknown action", `{"action":"proceed"}`, true},
		{"non-string action", `{"action":1}`, true},
		{"block without directive", `{"action":"block"}`, true},
		{"block whose directive allows", `{"action":"block","hook_output":{"decision":"allow","reason":"x"}}`, true},
		{"allow with a block directive", `{"action":"allow","hook_output":{"decision":"block","reason":"x"}}`, true},
		{"observe allow", `{"action":"allow"}`, false},
		{"observe alert", `{"action":"alert"}`, false},
		{"block with directive", `{"action":"block","hook_output":{"decision":"block","reason":"policy"}}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := run(t, "hermes", ok(tc.body), func(o *Options) {
				o.Event = "pre_tool_call"
				o.FailMode = "closed"
				o.ManagedEnterprise = true
				o.ExplainUnenrolledAccount = true
				o.Stdin = strings.NewReader(`{"hook_event_name":"pre_tool_call","tool_name":"terminal"}`)
			})
			if result.code != 0 {
				t.Fatalf("code %d, want 0 (stderr %q)", result.code, result.stderr)
			}
			if !tc.blocks {
				if strings.TrimSpace(result.stdout) != "" {
					t.Fatalf("stdout = %q, want the neutral result", result.stdout)
				}
				return
			}
			var body map[string]string
			if err := json.Unmarshal(bytes.TrimSpace([]byte(result.stdout)), &body); err != nil ||
				(body["action"] != "block" && body["decision"] != "block") {
				t.Fatalf("stdout = %q, want a Hermes block directive", result.stdout)
			}
		})
	}
}

type failingStdin struct{}

func (failingStdin) Read([]byte) (int, error) { return 0, errors.New("stdin closed") }

// rel-1-0-3 B-20 review item 2: the installed Windows Hermes command binds no
// event (it is read from stdin). Input refused before the event is read, too
// large or unreadable, blocks a managed invocation unless the bounded prefix
// names an event that is no tool call.
func TestManagedHermesUnboundEventBlocksRefusedInput(t *testing.T) {
	const llmCall = `{"hook_event_name":"pre_llm_call","messages":["` + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + `"]}`
	const toolCall = `{"hook_event_name":"pre_tool_call","tool_input":{"command":"` + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + `"}}`
	const disagree = `{"hook_event_name":"pre_llm_call","event":"pre_tool_call","tool_input":"` + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + `"}`
	for _, tc := range []struct {
		name    string
		stdin   func() io.Reader
		maxBody int64
		blocks  bool
	}{
		{"oversized before the event", func() io.Reader { return strings.NewReader(toolCall) }, 4, true},
		{"oversized tool call", func() io.Reader { return strings.NewReader(toolCall) }, 40, true},
		{"oversized with disagreeing events", func() io.Reader { return strings.NewReader(disagree) }, 60, true},
		{"unreadable stdin", func() io.Reader { return failingStdin{} }, 0, true},
		{"oversized llm call", func() io.Reader { return strings.NewReader(llmCall) }, 40, false},
	} {
		for _, managed := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s managed=%v", tc.name, managed), func(t *testing.T) {
				var home string
				result := run(t, "hermes", ok(`{"action":"allow"}`), func(o *Options) {
					o.Event = ""
					o.FailMode = "open"
					if managed {
						o.FailMode = "closed"
					}
					o.ManagedEnterprise = managed
					o.ExplainUnenrolledAccount = managed
					o.Stdin = tc.stdin()
					if tc.maxBody > 0 {
						o.MaxBody = tc.maxBody
					}
					home = o.Home
					o.FailureLogHome = userLogHome(o.Home)
				})
				if result.code != 0 {
					t.Fatalf("code %d, want 0 (stderr %q)", result.code, result.stderr)
				}
				if managed && tc.blocks {
					message := hermesBlockMessage(t, result.stdout)
					if !strings.HasPrefix(message, "DefenseClaw blocked this tool call: ") {
						t.Fatalf("message %q, want a tool-call block", message)
					}
					if got := lastHookFailure(t, home)["fail_mode"]; got != "closed" {
						t.Fatalf("logged fail_mode = %q, want closed", got)
					}
					return
				}
				if strings.Contains(result.stdout, `"block"`) {
					t.Fatalf("stdout %q, want the neutral result", result.stdout)
				}
			})
		}
	}
}

// rel-1-0-3 GAP-0202: an in-cap managed Hermes input whose installed
// command binds no event and whose top-level hook_event_name and event
// fields disagree may be a tool call, so a managed hook outside Secure
// Client blocks it with the Hermes directive, logs fail_mode closed and
// does not ask the gateway. Agreeing fields, a bound event, per-user and
// Secure Client hooks keep the gateway's verdict.
func TestManagedHermesDisagreeingEventFieldsBlock(t *testing.T) {
	// The 115-byte BW-03 case (e) input.
	const disagree = `{"hook_event_name":"pre_tool_call","event":"pre_llm_call","tool_name":"terminal","tool_input":{"command":"echo x"}}`
	const agree = `{"hook_event_name":"pre_tool_call","event":"pre_tool_call","tool_name":"terminal","tool_input":{"command":"echo x"}}`
	for _, tc := range []struct {
		name                  string
		stdin, event          string
		managed, secureClient bool
		blocks                bool
	}{
		{name: "managed, fields disagree", stdin: disagree, managed: true, blocks: true},
		{name: "managed, fields disagree in the other order", stdin: `{"hook_event_name":"pre_llm_call","event":"pre_tool_call"}`, managed: true, blocks: true},
		{name: "managed, fields agree", stdin: agree, managed: true},
		{name: "managed, bound event", stdin: disagree, event: "pre_llm_call", managed: true},
		{name: "managed Secure Client, fields disagree", stdin: disagree, managed: true, secureClient: true},
		{name: "per-user, fields disagree", stdin: disagree},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var home string
			gateway := ok(`{"action":"allow"}`)
			result := run(t, "hermes", gateway, func(o *Options) {
				o.Event = tc.event
				o.FailMode = "open"
				if tc.managed {
					o.FailMode = "closed"
				}
				o.ManagedEnterprise = tc.managed
				o.ExplainUnenrolledAccount = tc.managed
				o.SecureClient = tc.secureClient
				o.Stdin = strings.NewReader(tc.stdin)
				home = o.Home
				o.FailureLogHome = userLogHome(o.Home)
			})
			if result.code != 0 {
				t.Fatalf("code %d, want 0 (stderr %q)", result.code, result.stderr)
			}
			if !tc.blocks {
				if strings.Contains(result.stdout, `"block"`) {
					t.Fatalf("stdout %q, want the gateway's allow (neutral result)", result.stdout)
				}
				return
			}
			message := hermesBlockMessage(t, result.stdout)
			if !strings.HasPrefix(message, "DefenseClaw blocked this tool call: its hook input names two different events") {
				t.Fatalf("message %q, want the two-events tool-call block", message)
			}
			entry := lastHookFailure(t, home)
			if entry["fail_mode"] != "closed" || entry["reason"] != managedHermesEventConflictReason {
				t.Fatalf("hook failure %v, want fail_mode closed and the two-events reason", entry)
			}
			if gateway.requests != 0 {
				t.Fatalf("gateway asked %d times, want 0", gateway.requests)
			}
		})
	}
}
