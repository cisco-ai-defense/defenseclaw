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
		{sessionStopEvent{connector: "devin", payload: `{"hook_event_name":"PreToolUse"}`}, 2, `"decision":"block"`},
		{sessionStopEvent{connector: "copilot", event: "permissionRequest"}, 0, `"behavior":"deny"`},
		// A payload that names no event, or names a stop only in a field
		// the connector does not read, is not a stop event.
		{sessionStopEvent{connector: "claudecode", payload: `{}`}, 2, ""},
		{sessionStopEvent{connector: "devin", payload: `{"hook_event_name":"Stop","event":"PreToolUse"}`}, 2, `"decision":"block"`},
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
			if (tc.code >= 0 && r.code != tc.code) || !strings.Contains(r.stdout, tc.stdout) {
				t.Fatalf("%s: want a block, got code=%d stdout=%q stderr=%q", name, r.code, r.stdout, r.stderr)
			}
		}
	}
}

// Outside the standalone profile (the Secure Client profile and every other
// managed hook) a stop event keeps its fail-closed result.
func TestManagedFailClosedStopOutsideStandaloneIsUnchanged(t *testing.T) {
	for _, tc := range []struct {
		sessionStopEvent
		code   int
		stdout string
	}{
		{sessionStopEvent{connector: "claudecode", payload: `{"hook_event_name":"Stop"}`}, 2, ""},
		{sessionStopEvent{connector: "codex", event: "Stop"}, 0, `{"decision":"block","reason":"DefenseClaw hook failed closed"}`},
		{sessionStopEvent{connector: "devin", payload: `{"hook_event_name":"Stop"}`}, 2, `{"decision":"block","reason":"DefenseClaw hook failed closed"}`},
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
