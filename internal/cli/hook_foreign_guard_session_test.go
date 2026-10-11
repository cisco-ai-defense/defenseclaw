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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// runEvent runs the hook-time guard for connector with a payload carrying
// event and, when set, the session ID under key.
func (f *foreignGuardFixture) runEvent(t *testing.T, connector, event, key, session string) hookexec.Options {
	t.Helper()
	payload := map[string]any{"hook_event_name": event, "cwd": filepath.Join(f.project, "src")}
	if session != "" {
		payload[key] = session
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	opts := hookexec.Options{Connector: connector, ManagedEnterprise: true, Stdin: bytes.NewReader(data), Stderr: io.Discard}
	applyEnterpriseForeignHookGuard(&opts)
	return opts
}

func (f *foreignGuardFixture) guard(connector string) {
	f.summary.Connectors[connector] = enterprisepolicy.PublicConnectorPolicy{Route: enterprisepolicy.RouteMachinePolicy, ForeignHooks: config.ForeignHooksRemove, Guard: true}
}

const claudeForeignHook = `{"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "./rewrite.sh"}]}]}}`

// Claude Code keeps running the hooks it read at session start. A rewriting
// hook present at SessionStart and deleted afterwards (by hand, or by the
// hook's own SessionStart step) must keep the session's tool calls denied,
// with a message that says to restart the agent.
func TestForeignHookGuardKeepsDenyingASessionThatStartedWithAForeignHook(t *testing.T) {
	fixture := newPortableForeignGuardFixture(t, config.ForeignHooksRemove)
	fixture.guard("claudecode")
	foreign := filepath.Join(fixture.project, ".claude", "settings.local.json")
	fixture.write(t, foreign, claudeForeignHook)

	start := fixture.runEvent(t, "claudecode", "SessionStart", "session_id", "s-1")
	if !strings.HasPrefix(start.ManagedRuntimeFailure, hookexec.ForeignHookBlockedReasonPrefix) || !strings.Contains(start.ManagedRuntimeFailure, foreign) || !strings.Contains(start.ManagedRuntimeFailure, "restart the agent") {
		t.Fatalf("SessionStart with a foreign hook must deny, name the file and say to restart the agent: %q", start.ManagedRuntimeFailure)
	}

	if err := os.Remove(foreign); err != nil {
		t.Fatal(err)
	}
	// A user can remove the old user-owned session record; the gateway-held
	// state still keeps the session blocked.
	if err := os.RemoveAll(filepath.Join(fixture.home, ".defenseclaw", "foreign-hook-sessions")); err != nil {
		t.Fatal(err)
	}
	later := fixture.runEvent(t, "claudecode", "PreToolUse", "session_id", "s-1")
	if !later.ManagedEnterprise || !strings.HasPrefix(later.ManagedRuntimeFailure, hookexec.ForeignHookBlockedReasonPrefix) {
		t.Fatalf("the session's tool calls must stay denied after the hook is deleted: %+v", later)
	}
	for _, want := range []string{"When this agent session started", foreign, "restart the agent"} {
		if !strings.Contains(later.ManagedRuntimeFailure, want) {
			t.Fatalf("the session denial must say %q: %q", want, later.ManagedRuntimeFailure)
		}
	}
	blocks, _, err := enterprisepolicy.CollectForeignHookBlocks(fixture.home, time.Now())
	if err != nil || len(blocks) != 1 || blocks[0].Path != foreign || blocks[0].Count != 2 {
		t.Fatalf("both blocks are recorded for the guardian under the hook file: %+v %v", blocks, err)
	}

	// A restarted agent starts a new session from the clean files.
	if fresh := fixture.runEvent(t, "claudecode", "SessionStart", "session_id", "s-2"); fresh.ManagedRuntimeFailure != "" {
		t.Fatalf("a new session after the hook is gone must allow: %q", fresh.ManagedRuntimeFailure)
	}
	if fresh := fixture.runEvent(t, "claudecode", "PreToolUse", "session_id", "s-2"); fresh.ManagedRuntimeFailure != "" {
		t.Fatalf("the new session's tool calls must allow: %q", fresh.ManagedRuntimeFailure)
	}
}

func TestForeignHookGuardDeniesWhenGatewaySessionStateIsUnavailable(t *testing.T) {
	fixture := newPortableForeignGuardFixture(t, config.ForeignHooksRemove)
	fixture.guard("claudecode")
	fixture.process = "agent-process"
	hookForeignGuardExchange = func(string, string, time.Time, enterprisepolicy.SessionExchange) (enterprisepolicy.GuardDecision, error) {
		return enterprisepolicy.GuardDecision{}, os.ErrPermission
	}
	decision := fixture.runEvent(t, "claudecode", "SessionStart", "session_id", "s-1")
	if !strings.HasPrefix(decision.ManagedRuntimeFailure, hookexec.ForeignHookBlockedReasonPrefix) || !strings.Contains(decision.ManagedRuntimeFailure, "restart the agent") {
		t.Fatalf("unavailable gateway state must block the hook: %q", decision.ManagedRuntimeFailure)
	}
	// No hook is involved here (the usual cause is a stopped or restarting
	// gateway), so the reason names the gateway and does not ask the user to
	// remove a hook.
	if !strings.Contains(decision.ManagedRuntimeFailure, "with its gateway") || strings.Contains(decision.ManagedRuntimeFailure, "unapproved hook") {
		t.Fatalf("the unavailable-gateway reason must name the gateway, not a hook: %q", decision.ManagedRuntimeFailure)
	}
	// GAP-0578: a stopped gateway is no foreign-hook finding; the block uses
	// the not-running reason every managed hook uses.
	hookForeignGuardExchange = func(string, string, time.Time, enterprisepolicy.SessionExchange) (enterprisepolicy.GuardDecision, error) {
		return enterprisepolicy.GuardDecision{}, fmt.Errorf("dial hook socket: %w", hookexec.ErrManagedGatewayNotRunning)
	}
	if stopped := fixture.runEvent(t, "claudecode", "SessionStart", "session_id", "s-2"); stopped.ManagedRuntimeFailure != hookexec.ManagedGatewayNotRunningReason {
		t.Fatalf("a stopped gateway must block with the not-running reason: %q", stopped.ManagedRuntimeFailure)
	}
}

// A hook that appears after the session started denies the calls that find
// it, but does not block the session: once it is removed, the session's
// calls are allowed again.
func TestForeignHookGuardBlocksTheSessionOnlyForAHookPresentAtStart(t *testing.T) {
	fixture := newPortableForeignGuardFixture(t, config.ForeignHooksRemove)
	fixture.guard("cursor")
	fixture.process = "linux::8181:1"
	if start := fixture.runEvent(t, "cursor", "sessionStart", "conversation_id", "c-1"); start.ManagedRuntimeFailure != "" {
		t.Fatalf("a clean session start must allow: %q", start.ManagedRuntimeFailure)
	}
	foreign := filepath.Join(fixture.project, ".cursor", "hooks.json")
	fixture.write(t, foreign, `{"version": 1, "hooks": {"preToolUse": [{"command": "./rewrite.sh"}]}}`)
	call := fixture.runEvent(t, "cursor", "preToolUse", "conversation_id", "c-1")
	if !strings.HasPrefix(call.ManagedRuntimeFailure, hookexec.ForeignHookBlockedReasonPrefix) || strings.Contains(call.ManagedRuntimeFailure, "restart the agent") {
		t.Fatalf("a hook found after the session start must deny the call without blocking the session: %q", call.ManagedRuntimeFailure)
	}
	if err := os.Remove(foreign); err != nil {
		t.Fatal(err)
	}
	if later := fixture.runEvent(t, "cursor", "preToolUse", "conversation_id", "c-1"); later.ManagedRuntimeFailure != "" {
		t.Fatalf("once the hook is removed the session must be allowed: %q", later.ManagedRuntimeFailure)
	}

	// A hook present at the start blocks the session under each agent's own
	// session ID: Cursor's conversation_id and Copilot's sessionId.
	t.Run("each agent's session id", func(t *testing.T) {
		for _, tc := range []struct{ connector, start, call, key, file, body string }{
			{"cursor", "sessionStart", "preToolUse", "conversation_id", filepath.Join(".cursor", "hooks.json"), `{"version": 1, "hooks": {"preToolUse": [{"command": "./rewrite.sh"}]}}`},
			{"copilot", "sessionStart", "preToolUse", "sessionId", filepath.Join(".github", "hooks", "x.json"), `{"hooks": {"preToolUse": [{"bash": "./rewrite.sh"}]}}`},
		} {
			fixture := newPortableForeignGuardFixture(t, config.ForeignHooksRemove)
			fixture.guard(tc.connector)
			foreign := filepath.Join(fixture.project, tc.file)
			fixture.write(t, foreign, tc.body)
			if start := fixture.runEvent(t, tc.connector, tc.start, tc.key, "c-1"); start.ManagedRuntimeFailure == "" {
				t.Fatalf("%s: a foreign hook at session start must deny", tc.connector)
			}
			if err := os.Remove(foreign); err != nil {
				t.Fatal(err)
			}
			if later := fixture.runEvent(t, tc.connector, tc.call, tc.key, "c-1"); !strings.Contains(later.ManagedRuntimeFailure, "When this agent session started") {
				t.Fatalf("%s: the session must stay denied through %s: %q", tc.connector, tc.key, later.ManagedRuntimeFailure)
			}
			if other := fixture.runEvent(t, tc.connector, tc.call, tc.key, "c-2"); other.ManagedRuntimeFailure != "" {
				t.Fatalf("%s: another session is not affected: %q", tc.connector, other.ManagedRuntimeFailure)
			}
		}
	})
}

// A session the same agent process clears or compacts into gets a new
// session ID but keeps the hooks the process loaded: the agent process
// carries the block. A restarted agent resuming the session starts clean.
func TestForeignHookGuardHoldsTheBlockForTheAgentProcess(t *testing.T) {
	fixture := newPortableForeignGuardFixture(t, config.ForeignHooksRemove)
	fixture.guard("claudecode")
	fixture.process = "linux::4242:100"
	foreign := filepath.Join(fixture.project, ".claude", "settings.json")
	fixture.write(t, foreign, claudeForeignHook)
	if start := fixture.runEvent(t, "claudecode", "SessionStart", "session_id", "s-1"); start.ManagedRuntimeFailure == "" {
		t.Fatal("a foreign hook at session start must deny")
	}
	if err := os.Remove(foreign); err != nil {
		t.Fatal(err)
	}
	if cleared := fixture.runEvent(t, "claudecode", "SessionStart", "session_id", "s-2"); !strings.Contains(cleared.ManagedRuntimeFailure, foreign) {
		t.Fatalf("a cleared session in the same agent process must stay denied: %q", cleared.ManagedRuntimeFailure)
	}
	if call := fixture.runEvent(t, "claudecode", "PreToolUse", "session_id", "s-2"); call.ManagedRuntimeFailure == "" {
		t.Fatal("the cleared session's tool calls must stay denied")
	}
	fixture.process = "linux::5151:200"
	if resumed := fixture.runEvent(t, "claudecode", "SessionStart", "session_id", "s-1"); resumed.ManagedRuntimeFailure != "" {
		t.Fatalf("a restarted agent resuming the session must allow: %q", resumed.ManagedRuntimeFailure)
	}
	if call := fixture.runEvent(t, "claudecode", "PreToolUse", "session_id", "s-1"); call.ManagedRuntimeFailure != "" {
		t.Fatalf("the resumed session's tool calls must allow: %q", call.ManagedRuntimeFailure)
	}
}

// The session state applies only while the connector's policy removes
// foreign hooks: an administrator who relaxes it to report or allow lifts
// the block.
func TestForeignHookGuardSessionStateNeedsRemoveMode(t *testing.T) {
	fixture := newPortableForeignGuardFixture(t, config.ForeignHooksRemove)
	fixture.guard("claudecode")
	foreign := filepath.Join(fixture.project, ".claude", "settings.local.json")
	fixture.write(t, foreign, claudeForeignHook)
	fixture.runEvent(t, "claudecode", "SessionStart", "session_id", "s-1")
	if err := os.Remove(foreign); err != nil {
		t.Fatal(err)
	}
	policy := fixture.summary.Connectors["claudecode"]
	policy.ForeignHooks = config.ForeignHooksReport
	fixture.summary.Connectors["claudecode"] = policy
	if call := fixture.runEvent(t, "claudecode", "PreToolUse", "session_id", "s-1"); call.ManagedRuntimeFailure != "" {
		t.Fatalf("report mode must not deny from the session state: %q", call.ManagedRuntimeFailure)
	}
	policy.ForeignHooks = config.ForeignHooksRemove
	fixture.summary.Connectors["claudecode"] = policy
	if call := fixture.runEvent(t, "claudecode", "PreToolUse", "session_id", "s-1"); call.ManagedRuntimeFailure == "" {
		t.Fatal("back in remove mode the session is still blocked")
	}
}

// The in-agent plugin check (OpenCode, Amp) is keyed by the agent process,
// which loads plugins once: a plugin present at the startup check keeps the
// process denied after it is deleted, and a new process starts clean.
func TestForeignHookCheckHoldsTheBlockForThePluginProcess(t *testing.T) {
	fixture := newPortableForeignGuardFixture(t, config.ForeignHooksRemove)
	t.Setenv("XDG_CONFIG_HOME", "")
	fixture.summary.Connectors["opencode"] = enterprisepolicy.PublicConnectorPolicy{Route: enterprisepolicy.RoutePerUser, ForeignHooks: config.ForeignHooksRemove, Guard: true}
	fixture.process = "linux::777:1"
	check := func(event string) foreignHookCheckResult {
		t.Helper()
		var out bytes.Buffer
		payload, err := json.Marshal(map[string]string{"hook_event_name": event, "cwd": fixture.project})
		if err != nil {
			t.Fatal(err)
		}
		runForeignHookCheck("opencode", bytes.NewReader(payload), &out)
		var result foreignHookCheckResult
		if err := json.Unmarshal(out.Bytes(), &result); err != nil {
			t.Fatalf("the answer must be JSON: %v: %q", err, out.String())
		}
		return result
	}
	foreign := filepath.Join(fixture.project, ".opencode", "plugins", "rewrite.js")
	fixture.write(t, foreign, "export const x = {}")
	if result := check("defenseclaw.plugin.loaded"); !result.Deny {
		t.Fatalf("a foreign plugin at startup must deny: %+v", result)
	}
	if err := os.Remove(foreign); err != nil {
		t.Fatal(err)
	}
	if result := check("tool.execute.before"); !result.Deny || !strings.Contains(result.Reason, "restart the agent") {
		t.Fatalf("the process that loaded the plugin must stay denied: %+v", result)
	}
	fixture.process = "linux::778:2"
	if result := check("defenseclaw.plugin.loaded"); result.Deny {
		t.Fatalf("a restarted agent without the plugin must allow: %+v", result)
	}
}
