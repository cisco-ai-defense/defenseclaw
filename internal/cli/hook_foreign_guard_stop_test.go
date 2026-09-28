// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// foreignGuardStopCase is one connector's session: where its foreign hook
// lives, the payload's session key, and its events.
type foreignGuardStopCase struct {
	connector, file, body, key string
	// bound: the command binds the event (--event), as Codex and Copilot
	// registrations do; the others read it from the payload.
	bound       bool
	start, tool string
	stops       []string
	// deny reports whether a result is the connector's tool-call block.
	deny func(code int, stdout string) bool
	// allow is the connector's neutral stdout on a stop event.
	allow string
}

// hookResult is one full hook invocation: the guard, then hookexec.
type hookResult struct {
	code           int
	stdout, stderr string
}

func (f *foreignGuardFixture) runHook(t *testing.T, tc foreignGuardStopCase, event, session string) hookResult {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"hook_event_name": event, "cwd": filepath.Join(f.project, "src"), tc.key: session})
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	opts := hookexec.Options{
		Connector:         tc.connector,
		ManagedEnterprise: true,
		FailMode:          "closed",
		Home:              filepath.Join(f.home, "managed-data"),
		Stdin:             bytes.NewReader(payload),
		Stdout:            &stdout,
		Stderr:            &stderr,
	}
	if tc.bound {
		opts.Event = event
	}
	if tc.connector == "codex" {
		opts.HookContractID = "codex-hooks-v4"
	}
	applyEnterpriseForeignHookGuard(&opts)
	if !strings.HasPrefix(opts.ManagedRuntimeFailure, hookexec.ForeignHookBlockedReasonPrefix) {
		t.Fatalf("%s %s: the session must be blocked by the guard: %+v", tc.connector, event, opts)
	}
	code := hookexec.Run(context.Background(), opts)
	return hookResult{code: code, stdout: strings.TrimSpace(stdout.String()), stderr: stderr.String()}
}

// recordedBlockEvents lists the events of the blocks the hook recorded for
// the guardian, in order.
func recordedBlockEvents(t *testing.T, home string) []string {
	t.Helper()
	data, err := os.ReadFile(enterprisepolicy.BlockRecordPath(home))
	if err != nil {
		t.Fatalf("the blocks must be recorded for the guardian: %v", err)
	}
	events := []string{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		var record enterprisepolicy.BlockRecord
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			t.Fatalf("block record: %v: %s", err, scanner.Text())
		}
		events = append(events, record.Event)
	}
	return events
}

// A session the foreign-hook guard blocks must still be able to stop. The
// agents answer a block on a stop event by going on (Claude Code, Codex,
// Devin and Copilot continue the turn; Cursor submits a stop hook's
// followup_message as the next prompt), so a blocked session looped until
// the agent restarted. Stop and session-end events get the connector's
// neutral allow and are still recorded for the guardian; the session's tool
// calls stay denied.
func TestForeignHookGuardLetsABlockedSessionStop(t *testing.T) {
	codeTwo := func(code int, _ string) bool { return code == 2 }
	for _, tc := range []foreignGuardStopCase{
		{
			connector: "claudecode", file: filepath.Join(".claude", "settings.local.json"), body: claudeForeignHook, key: "session_id",
			start: "SessionStart", tool: "PreToolUse", stops: []string{"Stop", "SubagentStop", "SessionEnd"},
			deny: codeTwo,
		},
		{
			connector: "codex", file: filepath.Join(".codex", "hooks.json"), body: claudeForeignHook, key: "session_id", bound: true,
			start: "SessionStart", tool: "PreToolUse", stops: []string{"Stop", "SubagentStop", "SessionEnd"},
			deny: func(code int, stdout string) bool {
				return code == 0 && strings.Contains(stdout, `"permissionDecision":"deny"`)
			},
		},
		{
			connector: "cursor", file: filepath.Join(".cursor", "hooks.json"), body: `{"version": 1, "hooks": {"preToolUse": [{"command": "./rewrite.sh"}]}}`, key: "conversation_id",
			start: "sessionStart", tool: "preToolUse", stops: []string{"stop", "subagentStop", "sessionEnd"},
			deny: func(code int, stdout string) bool {
				return code == 2 && strings.Contains(stdout, `"permission":"deny"`)
			},
			allow: `{}`,
		},
		{
			connector: "devin", file: filepath.Join(".devin", "config.json"), body: claudeForeignHook, key: "session_id",
			start: "SessionStart", tool: "PreToolUse", stops: []string{"Stop", "SessionEnd"},
			deny: func(code int, stdout string) bool {
				return code == 2 && strings.Contains(stdout, `"decision":"block"`)
			},
		},
		{
			connector: "copilot", file: filepath.Join(".github", "hooks", "x.json"), body: `{"hooks": {"preToolUse": [{"bash": "./rewrite.sh"}]}}`, key: "sessionId", bound: true,
			start: "sessionStart", tool: "preToolUse", stops: []string{"agentStop", "subagentStop", "sessionEnd"},
			deny: func(code int, stdout string) bool {
				return code == 0 && strings.Contains(stdout, `"permissionDecision":"deny"`)
			},
		},
	} {
		t.Run(tc.connector, func(t *testing.T) {
			fixture := newPortableForeignGuardFixture(t, config.ForeignHooksRemove)
			fixture.guard(tc.connector)
			foreign := filepath.Join(fixture.project, tc.file)
			fixture.write(t, foreign, tc.body)
			fixture.runHook(t, tc, tc.start, "s-1")
			if err := os.Remove(foreign); err != nil {
				t.Fatal(err)
			}

			want := []string{tc.start}
			for _, stop := range tc.stops {
				result := fixture.runHook(t, tc, stop, "s-1")
				if result.code != 0 || result.stdout != tc.allow {
					t.Fatalf("%s: a blocked session's stop event must get the neutral allow %q: code=%d stdout=%q stderr=%q", stop, tc.allow, result.code, result.stdout, result.stderr)
				}
				want = append(want, stop)
			}
			result := fixture.runHook(t, tc, tc.tool, "s-1")
			if !tc.deny(result.code, result.stdout) {
				t.Fatalf("%s: the session's tool calls must stay denied: code=%d stdout=%q stderr=%q", tc.tool, result.code, result.stdout, result.stderr)
			}
			if !strings.Contains(result.stdout+result.stderr, "When this agent session started") {
				t.Fatalf("%s: the denial must say the session is blocked: stdout=%q stderr=%q", tc.tool, result.stdout, result.stderr)
			}
			want = append(want, tc.tool)

			if got := recordedBlockEvents(t, fixture.home); strings.Join(got, ",") != strings.Join(want, ",") {
				t.Fatalf("every blocked event, stop events included, must be recorded for the guardian: got %v, want %v", got, want)
			}
		})
	}
}
