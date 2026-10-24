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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const foreignHookStopReason = ForeignHookBlockedReasonPrefix + " When this agent session started, the project file /repo/.claude/settings.local.json defined a hook. Restart the agent."

// sessionStopCause is one way a managed hook denies without a gateway
// verdict: a standalone outage that fails closed, or the foreign-hook guard.
type sessionStopCause struct {
	name    string
	foreign bool
	rt      func() *stubRT
	mutate  func(*Options)
}

var sessionStopCauses = []sessionStopCause{
	{
		// The descriptor names no hook socket: the CLI hands hookexec the
		// runtime failure and marks it as the standalone profile's.
		name:   "hook socket missing",
		rt:     func() *stubRT { return ok(`{"action":"allow"}`) },
		mutate: func(o *Options) { o.ManagedRuntimeFailure = "enterprise_managed_hook_socket_missing" },
	},
	{name: "empty ManagedUnixSocket", rt: func() *stubRT { return ok(`{"action":"allow"}`) }, mutate: func(o *Options) { o.ManagedUnixSocket = "" }},
	{
		name:   "transport error",
		rt:     func() *stubRT { return &stubRT{err: errors.New("dial unix: connection refused")} },
		mutate: func(o *Options) { o.ManagedUnixSocket = "/run/defenseclaw-hook/hook.sock" },
	},
	{name: "unusable gateway response", rt: func() *stubRT { return ok("not json") }, mutate: func(o *Options) { o.ManagedUnixSocket = "/run/defenseclaw-hook/hook.sock" }},
	{
		name:    "foreign-hook block",
		foreign: true,
		rt:      func() *stubRT { return ok(`{"action":"allow"}`) },
		mutate:  func(o *Options) { o.ManagedRuntimeFailure = foreignHookStopReason },
	},
}

type sessionStopEvent struct {
	connector, event, payload string
}

func (ev sessionStopEvent) String() string { return ev.connector + " " + ev.event + ev.payload }

// runSessionStop runs one managed hook that denies for cause and returns the
// result and the managed hook failure log.
func runSessionStop(t *testing.T, cause sessionStopCause, ev sessionStopEvent, standalone bool) (runResult, string) {
	t.Helper()
	var home string
	rt := cause.rt()
	r := run(t, ev.connector, rt, func(o *Options) {
		o.ManagedEnterprise = true
		o.Event = ev.event
		if ev.payload != "" {
			o.Stdin = strings.NewReader(ev.payload)
		}
		if !cause.foreign {
			o.ManagedStandalone = standalone
			o.FailMode = "closed"
			o.StrictAvailability = true
			o.ManagedServiceUID = 0
			if ev.payload == "" && ev.connector == "codex" {
				o.Stdin = strings.NewReader(`{"hook_event_name":"` + ev.event + `"}`)
			}
		}
		cause.mutate(o)
		home = o.Home
		o.FailureLogHome = userLogHome(o.Home)
	})
	if cause.foreign && rt.requests != 0 {
		t.Fatalf("%s: a foreign-hook block must not contact the gateway", ev)
	}
	log, _ := os.ReadFile(filepath.Join(home, "logs", "hook-failures.jsonl"))
	return r, string(log)
}

// A block on a stop event does not deny anything, it keeps the agent going:
// Claude Code, Codex, Devin and Copilot continue when a stop hook blocks, and
// Cursor submits a stop hook's followup_message as the next prompt. So a
// standalone outage, or a session the foreign-hook guard blocked, would loop
// every turn. Stop and session-end events get the connector's neutral allow,
// logged as fail mode open; tool, prompt and session-start events keep the
// connector's native block.
func TestManagedSessionStopEventsAllowWhileOtherEventsStayBlocked(t *testing.T) {
	stops := []struct {
		sessionStopEvent
		stdout string
		// foreignOnly: only the foreign-hook block reaches the stop
		// handling; Copilot hooks fail open on an outage anyway.
		foreignOnly bool
	}{
		{sessionStopEvent{connector: "claudecode", payload: `{"hook_event_name":"Stop","stop_hook_active":false}`}, "", false},
		{sessionStopEvent{connector: "claudecode", payload: `{"hook_event_name":"SessionEnd"}`}, "", false},
		{sessionStopEvent{connector: "codex", event: "SubagentStop"}, "", false},
		{sessionStopEvent{connector: "cursor", payload: `{"hook_event_name":"stop"}`}, "{}", false},
		{sessionStopEvent{connector: "devin", payload: `{"hook_event_name":"Stop"}`}, "", false},
		{sessionStopEvent{connector: "copilot", event: "agentStop"}, "", true},
	}
	blocked := []struct {
		sessionStopEvent
		code   int // -1: the exit code differs by cause
		stdout string
	}{
		{sessionStopEvent{connector: "claudecode", payload: `{"hook_event_name":"PreToolUse"}`}, 2, ""},
		{sessionStopEvent{connector: "claudecode", payload: `{"hook_event_name":"UserPromptSubmit"}`}, 2, ""},
		{sessionStopEvent{connector: "codex", event: "SessionStart"}, 0, `"continue":false`},
		{sessionStopEvent{connector: "cursor", payload: `{"hook_event_name":"preToolUse"}`}, -1, `"permission":"deny"`},
		{sessionStopEvent{connector: "devin", payload: `{"hook_event_name":"PreToolUse"}`}, 2, ""},
		{sessionStopEvent{connector: "copilot", event: "permissionRequest"}, 0, `"behavior":"deny"`},
		// A payload that names no event, or names a stop only in a field
		// the connector does not read, is not a stop event.
		{sessionStopEvent{connector: "claudecode", payload: `{}`}, 2, ""},
		{sessionStopEvent{connector: "devin", payload: `{"hook_event_name":"Stop","event":"PreToolUse"}`}, 2, ""},
	}
	for _, cause := range sessionStopCauses {
		for _, tc := range stops {
			if tc.foreignOnly && !cause.foreign {
				continue
			}
			name := cause.name + ": " + tc.String()
			r, log := runSessionStop(t, cause, tc.sessionStopEvent, true)
			if r.code != 0 || strings.TrimSpace(r.stdout) != tc.stdout {
				t.Fatalf("%s: want the neutral allow %q, got code=%d stdout=%q stderr=%q", name, tc.stdout, r.code, r.stdout, r.stderr)
			}
			if !strings.Contains(log, `"fail_mode":"open"`) {
				t.Fatalf("%s: the denial must be logged with the allow it got: %s", name, log)
			}
			if cause.foreign && (!strings.Contains(log, `"category":"policy"`) || !strings.Contains(r.stderr, "/repo/.claude/settings.local.json")) {
				t.Fatalf("%s: the foreign-hook block must stay logged and explained: stderr=%q log=%s", name, r.stderr, log)
			}
			if !cause.foreign && !strings.HasPrefix(r.stderr, "DefenseClaw is not blocking the ") {
				t.Fatalf("%s: stderr = %q", name, r.stderr)
			}
		}
		for _, tc := range blocked {
			name := cause.name + ": " + tc.String()
			r, _ := runSessionStop(t, cause, tc.sessionStopEvent, true)
			code, stdout := tc.code, tc.stdout
			if !cause.foreign && tc.connector == "claudecode" {
				if strings.Contains(tc.payload, `"PreToolUse"`) {
					code, stdout = 0, `"permissionDecision":"deny"`
				} else if strings.Contains(tc.payload, `"UserPromptSubmit"`) {
					code, stdout = 0, `"decision":"block"`
				}
			}
			if (code >= 0 && r.code != code) || !strings.Contains(r.stdout, stdout) {
				t.Fatalf("%s: want a block, got code=%d stdout=%q stderr=%q", name, r.code, r.stdout, r.stderr)
			}
		}
	}
}

// The Secure Client profile (a managed hook that is neither standalone
// shape) keeps the fail-closed result of a stop event.
func TestSecureClientFailClosedStopIsUnchanged(t *testing.T) {
	for _, tc := range []struct {
		sessionStopEvent
		code   int
		stdout string
	}{
		{sessionStopEvent{connector: "claudecode", payload: `{"hook_event_name":"Stop"}`}, 2, ""},
		{sessionStopEvent{connector: "codex", event: "Stop"}, 0, `{"decision":"block","reason":"DefenseClaw hook failed closed"}`},
		{sessionStopEvent{connector: "devin", payload: `{"hook_event_name":"Stop"}`}, 2, "DefenseClaw hook failed closed"},
		// The runtime failure never reads Cursor's payload there: the event
		// stays unnamed, so Cursor gets exit 2 and an empty body.
		{sessionStopEvent{connector: "cursor", payload: `{"hook_event_name":"stop"}`}, 2, `{}`},
	} {
		r, _ := runSessionStop(t, sessionStopCauses[0], tc.sessionStopEvent, false)
		if r.code != tc.code || strings.TrimSpace(r.stdout) != tc.stdout {
			t.Fatalf("%s: want the unchanged fail-closed result, got code=%d stdout=%q stderr=%q", tc, r.code, r.stdout, r.stderr)
		}
	}
}

// GAP-1257: a foreign-hook block on Cursor's workspaceOpen or sessionStart
// (the first start in a folder) answers the neutral allow instead of exit 2,
// which left cursor-agent on "Trusting workspace..."; its tool calls and
// prompts stay blocked with the reason.
func TestForeignHookBlockLetsCursorOpenTheWorkspace(t *testing.T) {
	cause := sessionStopCauses[len(sessionStopCauses)-1]
	if !cause.foreign {
		t.Fatal("the last cause is not the foreign-hook block")
	}
	for _, event := range []string{"workspaceOpen", "sessionStart"} {
		r, log := runSessionStop(t, cause, sessionStopEvent{connector: "cursor", payload: `{"hook_event_name":"` + event + `"}`}, true)
		if r.code != 0 || strings.TrimSpace(r.stdout) != "{}" || !strings.Contains(log, `"fail_mode":"open"`) ||
			!strings.Contains(r.stderr, "/repo/.claude/settings.local.json") {
			t.Fatalf("%s: code=%d stdout=%q stderr=%q log=%s", event, r.code, r.stdout, r.stderr, log)
		}
	}
	for _, payload := range []string{`{"hook_event_name":"beforeSubmitPrompt"}`, `{"hook_event_name":"beforeShellExecution"}`} {
		r, _ := runSessionStop(t, cause, sessionStopEvent{connector: "cursor", payload: payload}, true)
		if !strings.Contains(r.stdout, "/repo/.claude/settings.local.json") {
			t.Fatalf("%s: want the block with its reason, got code=%d stdout=%q", payload, r.code, r.stdout)
		}
	}
}

// failClosedStopProfile is a hook profile whose failures fail closed.
type failClosedStopProfile struct {
	name string
	// transportOnly: strict availability closes transport failures only;
	// response failures follow the fail mode (open here).
	transportOnly bool
	mutate        func(*Options)
}

var failClosedStopProfiles = []failClosedStopProfile{
	{name: "per-user fail mode closed", mutate: func(o *Options) { o.FailMode = "closed" }},
	{name: "per-user strict availability", transportOnly: true, mutate: func(o *Options) { o.FailMode = "open"; o.StrictAvailability = true }},
}

// failClosedStopCauses are the per-user failures that fail closed: the
// gateway is down, answers 5xx or 401, or answers something unusable, and
// the hook token is missing.
var failClosedStopCauses = []struct {
	name     string
	response bool
	rt       func() *stubRT
	mutate   func(*Options)
}{
	{name: "gateway down", rt: func() *stubRT {
		return &stubRT{err: errors.New("dial tcp 127.0.0.1:8787: connect: connection refused")}
	}},
	{name: "gateway 502", rt: func() *stubRT { return &stubRT{status: 502, body: `{}`} }},
	{name: "gateway 401", response: true, rt: func() *stubRT { return &stubRT{status: 401, body: `{"error":"unauthorized"}`} }},
	{name: "unusable answer", response: true, rt: func() *stubRT { return ok("not json") }},
	{name: "missing token", rt: func() *stubRT { return ok(`{"action":"allow"}`) }, mutate: func(o *Options) {
		_ = os.Remove(filepath.Join(o.HookDir, ".token"))
		o.Token = ""
	}},
}

// #1140: a per-user hook that fails closed on a stop or session-end event
// answers the connector's neutral allow, because a block there only keeps
// the agent running (Codex retried a blocked Stop until the user pressed
// Esc). The failure is still logged, as fail mode open. Prompts, tool calls
// and session starts keep their fail-closed block.
func TestPerUserFailClosedStopEventsAllowWhileOtherEventsStayBlocked(t *testing.T) {
	stops := []struct {
		sessionStopEvent
		stdout string
	}{
		{sessionStopEvent{connector: "codex", event: "Stop"}, ""},
		{sessionStopEvent{connector: "codex", event: "SubagentStop"}, ""},
		{sessionStopEvent{connector: "claudecode", payload: `{"hook_event_name":"Stop","stop_hook_active":true}`}, ""},
		{sessionStopEvent{connector: "claudecode", payload: `{"hook_event_name":"SessionEnd"}`}, ""},
		{sessionStopEvent{connector: "cursor", payload: `{"hook_event_name":"stop"}`}, "{}"},
		{sessionStopEvent{connector: "devin", payload: `{"hook_event_name":"Stop"}`}, ""},
	}
	blocked := []struct {
		sessionStopEvent
		stdout string // a substring of the block body; "" means exit 2
	}{
		{sessionStopEvent{connector: "codex", event: "PreToolUse"}, `"permissionDecision":"deny"`},
		{sessionStopEvent{connector: "codex", event: "UserPromptSubmit"}, `"decision":"block"`},
		{sessionStopEvent{connector: "codex", event: "SessionStart"}, `"continue":false`},
		{sessionStopEvent{connector: "claudecode", payload: `{"hook_event_name":"PreToolUse","tool_name":"Bash"}`}, ""},
		{sessionStopEvent{connector: "cursor", payload: `{"hook_event_name":"preToolUse"}`}, `"permission":"deny"`},
		{sessionStopEvent{connector: "devin", payload: `{"hook_event_name":"PreToolUse"}`}, ""},
		// A payload whose two event fields disagree names no event.
		{sessionStopEvent{connector: "devin", payload: `{"hook_event_name":"Stop","event":"PreToolUse"}`}, ""},
		// An event field that is not a string names no event (the shell
		// hooks match, TestShellFailedStopEventMatchesTheNativeStopSet).
		{sessionStopEvent{connector: "devin", payload: `{"hook_event_name":"Stop","event":false}`}, ""},
		{sessionStopEvent{connector: "claudecode", payload: `{"hook_event_name":false,"event":"Stop"}`}, ""},
	}
	runEvent := func(profile failClosedStopProfile, cause int, ev sessionStopEvent) (runResult, string) {
		var home string
		r := run(t, ev.connector, failClosedStopCauses[cause].rt(), func(o *Options) {
			o.Event = ev.event
			if ev.payload != "" {
				o.Stdin = strings.NewReader(ev.payload)
			}
			profile.mutate(o)
			if m := failClosedStopCauses[cause].mutate; m != nil {
				m(o)
			}
			home = o.Home
			o.FailureLogHome = userLogHome(o.Home)
		})
		log, _ := os.ReadFile(filepath.Join(home, "logs", "hook-failures.jsonl"))
		return r, string(log)
	}
	for _, profile := range failClosedStopProfiles {
		for i, cause := range failClosedStopCauses {
			if profile.transportOnly && cause.response {
				continue
			}
			for _, tc := range stops {
				name := profile.name + ", " + cause.name + ": " + tc.String()
				r, log := runEvent(profile, i, tc.sessionStopEvent)
				if r.code != 0 || strings.TrimSpace(r.stdout) != tc.stdout {
					t.Errorf("%s: want the neutral allow %q, got code=%d stdout=%q stderr=%q", name, tc.stdout, r.code, r.stdout, r.stderr)
					continue
				}
				if !strings.HasPrefix(r.stderr, "DefenseClaw is not blocking the ") || !strings.Contains(log, `"fail_mode":"open"`) {
					t.Errorf("%s: the failure must be explained and logged as fail mode open: stderr=%q log=%s", name, r.stderr, log)
				}
			}
			for _, tc := range blocked {
				name := profile.name + ", " + cause.name + ": " + tc.String()
				r, _ := runEvent(profile, i, tc.sessionStopEvent)
				// A per-user Claude Code block for a down gateway is the
				// structured deny, exit 0 (rel-1-0-2 GAP-0486, claudeBlocked).
				claude := tc.connector == "claudecode" && tc.stdout == ""
				if claude && !claudeBlocked(r) ||
					!claude && (tc.stdout == "" && r.code != blockExit || tc.stdout != "" && !strings.Contains(r.stdout, tc.stdout)) {
					t.Errorf("%s: want the fail-closed block, got code=%d stdout=%q stderr=%q", name, r.code, r.stdout, r.stderr)
				}
				if strings.Contains(r.stderr, "is not blocking") {
					t.Errorf("%s: a blocked event must not claim the stop exception: %q", name, r.stderr)
				}
			}
		}
	}
}

// The fail-open per-user profile is unchanged: a stop event is allowed as
// before, with no stop-exception line.
func TestPerUserFailOpenStopIsUnchanged(t *testing.T) {
	r := run(t, "codex", &stubRT{err: errors.New("connection refused")}, func(o *Options) { o.Event = "Stop" })
	if r.code != 0 || r.stdout != "" || strings.Contains(r.stderr, "is not blocking") {
		t.Fatalf("code=%d stdout=%q stderr=%q", r.code, r.stdout, r.stderr)
	}
}

// A per-user Codex Stop whose payload is over the cap, or whose
// DefenseClaw home is unavailable under strict availability, gets the same
// neutral allow; Codex binds its event out of band, so the event is known
// before the payload is read. A PreToolUse stays blocked.
func TestPerUserCodexStopBeforeThePayloadIsRead(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Options)
	}{
		{"oversized payload", func(o *Options) { o.FailMode = "closed"; o.MaxBody = 4 }},
		{"home unavailable", func(o *Options) {
			o.StrictAvailability = true
			o.Home = filepath.Join(o.Home, "missing")
		}},
	} {
		stop := run(t, "codex", ok(`{"action":"allow"}`), func(o *Options) { tc.mutate(o); o.Event = "Stop" })
		if stop.code != 0 || stop.stdout != "" || !strings.HasPrefix(stop.stderr, "DefenseClaw is not blocking the Stop event") {
			t.Errorf("%s Stop: code=%d stdout=%q stderr=%q", tc.name, stop.code, stop.stdout, stop.stderr)
		}
		tool := run(t, "codex", ok(`{"action":"allow"}`), func(o *Options) { tc.mutate(o); o.Event = "PreToolUse" })
		if tool.code == 0 && !strings.Contains(tool.stdout, `"deny"`) && !strings.Contains(tool.stdout, `"block"`) {
			t.Errorf("%s PreToolUse: want a block, got code=%d stdout=%q stderr=%q", tc.name, tool.code, tool.stdout, tool.stderr)
		}
	}
}

// The Windows standalone hook (ExplainUnenrolledAccount) gives a stop event
// the neutral allow when its gateway service is stopped and when the account
// is not enrolled; tool calls stay blocked with the explanation.
func TestWindowsStandaloneStopEventsAllow(t *testing.T) {
	for _, reason := range []string{managedGatewayNotRunningReason, managedSIDUnregisteredReason, managedEnrollmentPendingReason} {
		for _, tc := range []struct {
			event   string
			allowed bool
		}{
			{"Stop", true}, {"SubagentStop", true}, {"PreToolUse", false}, {"UserPromptSubmit", false},
		} {
			rt := ok(`{"action":"allow"}`)
			r := run(t, "codex", rt, func(o *Options) {
				o.ManagedEnterprise = true
				o.ExplainUnenrolledAccount = true
				o.ManagedRuntimeFailure = reason
				o.Event = tc.event
			})
			name := reason + " " + tc.event
			if rt.requests != 0 {
				t.Fatalf("%s: a runtime failure must not contact the gateway", name)
			}
			if tc.allowed {
				if r.code != 0 || r.stdout != "" || !strings.HasPrefix(r.stderr, "DefenseClaw is not blocking the "+tc.event) {
					t.Errorf("%s: want the neutral allow, got code=%d stdout=%q stderr=%q", name, r.code, r.stdout, r.stderr)
				}
				continue
			}
			if !strings.Contains(r.stdout, `"deny"`) && !strings.Contains(r.stdout, `"block"`) {
				t.Errorf("%s: want a block, got code=%d stdout=%q stderr=%q", name, r.code, r.stdout, r.stderr)
			}
		}
	}
}
