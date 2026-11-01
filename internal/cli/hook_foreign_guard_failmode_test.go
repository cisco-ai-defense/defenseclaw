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
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// guardOutageConnectors are the guarded connectors whose foreign-hook check
// exchanges the session with the gateway.
func guardOutageConnectors() map[string]string {
	connectors := map[string]string{
		"opencode": "tool.execute.before", "copilot": "preToolUse",
		"cursor": "beforeShellExecution", "devin": "PreToolUse",
	}
	if runtime.GOOS != "windows" {
		connectors["hermes"] = "pre_tool_call"
		connectors["amp"] = "tool.call"
	}
	return connectors
}

// An online allow is only the answer to that call. When the next guarded
// call cannot reach the gateway, the 1.0.3 outage limit blocks it, even
// under administrator open and even with a clean earlier session (GAP-0352).
func TestForeignHookGuardOnlineAllowDoesNotApproveAnOpenOutage(t *testing.T) {
	for connector, event := range guardOutageConnectors() {
		t.Run(connector, func(t *testing.T) {
			fixture := newPortableForeignGuardFixture(t, config.ForeignHooksRemove)
			fixture.guard(connector)
			fixture.process = "agent-process"
			hookForeignGuardExchange = func(_ string, _ string, _, _ time.Time, update enterprisepolicy.SessionExchange) (enterprisepolicy.GuardDecision, error) {
				return update.Decision, nil
			}
			if got := runGuardEvent(t, fixture, connector, event, "s-1"); got.ManagedRuntimeFailure != "" {
				t.Fatalf("online clean call blocked: %q", got.ManagedRuntimeFailure)
			}
			notRunning := fmt.Errorf("dial hook socket: %w", hookexec.ErrManagedGatewayNotRunning)
			hookForeignGuardExchange = func(string, string, time.Time, time.Time, enterprisepolicy.SessionExchange) (enterprisepolicy.GuardDecision, error) {
				return enterprisepolicy.GuardDecision{}, notRunning
			}
			if got := runGuardEvent(t, fixture, connector, event, "s-1"); got.ManagedRuntimeFailure != hookexec.ManagedGatewayNotRunningReason {
				t.Fatalf("earlier allow approved an outage call: %q", got.ManagedRuntimeFailure)
			}
		})
	}
}

func runGuardEvent(t *testing.T, fixture *foreignGuardFixture, connector, event, session string) hookexec.Options {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"hook_event_name": event, "cwd": filepath.Join(fixture.project, "src"),
		"session_id": session, "sessionId": session})
	if err != nil {
		t.Fatal(err)
	}
	opts := hookexec.Options{Connector: connector, Event: event, ManagedEnterprise: true, Stdin: bytes.NewReader(payload), Stderr: io.Discard}
	applyEnterpriseForeignHookGuard(&opts)
	return opts
}

// Bounded review P1 (fallback): the gateway keeps the session record in its
// protected data directory, and the hook has no copy of it that the user
// cannot write. So when the gateway cannot answer the session exchange (it
// is stopped, restarting or not answering), a guarded connector's call is
// blocked with the outage's reason in every fail mode, open included, and an
// unapproved hook the scan finds blocks with its own reason.
func TestForeignHookGuardBlocksAGatewayOutageInEveryFailMode(t *testing.T) {
	notRunning := fmt.Errorf("dial hook socket: %w", hookexec.ErrManagedGatewayNotRunning)
	for connector, event := range guardOutageConnectors() {
		// The guard takes no fail mode: the exchange error alone decides.
		fixture := newPortableForeignGuardFixture(t, config.ForeignHooksRemove)
		fixture.guard(connector)
		fixture.process = "agent-process"
		hookForeignGuardExchange = func(string, string, time.Time, time.Time, enterprisepolicy.SessionExchange) (enterprisepolicy.GuardDecision, error) {
			return enterprisepolicy.GuardDecision{}, notRunning
		}
		got := runGuardEvent(t, fixture, connector, event, "s-1")
		if got.ManagedRuntimeFailure != hookexec.ManagedGatewayNotRunningReason {
			t.Fatalf("%s: a stopped gateway must block with the not-running reason: %q", connector, got.ManagedRuntimeFailure)
		}
	}
	fixture := newPortableForeignGuardFixture(t, config.ForeignHooksRemove)
	fixture.guard("copilot")
	fixture.process = "agent-process"
	hookForeignGuardExchange = func(string, string, time.Time, time.Time, enterprisepolicy.SessionExchange) (enterprisepolicy.GuardDecision, error) {
		return enterprisepolicy.GuardDecision{}, notRunning
	}
	foreign := filepath.Join(fixture.project, ".github", "hooks", "x.json")
	fixture.write(t, foreign, `{"hooks": {"preToolUse": [{"bash": "./rewrite.sh"}]}}`)
	found := fixture.runEvent(t, "copilot", "preToolUse", "sessionId", "s-1")
	if !strings.HasPrefix(found.ManagedRuntimeFailure, hookexec.ForeignHookBlockedReasonPrefix) || !strings.Contains(found.ManagedRuntimeFailure, foreign) {
		t.Fatalf("an unapproved hook must block with its own reason: %q", found.ManagedRuntimeFailure)
	}
}

// Bounded review P1: a session the gateway blocked at its start (an
// unapproved hook, since deleted while the agent still runs it) stays
// blocked when the gateway then stops and the administrator chose open, and
// no file under the account's home changes that: neither a record that says
// the session is not blocked, nor deleting every record there.
func TestForeignHookGuardKeepsAGatewaySessionBlockThroughAnOpenOutage(t *testing.T) {
	for connector, event := range guardOutageConnectors() {
		fixture := newPortableForeignGuardFixture(t, config.ForeignHooksRemove)
		fixture.guard(connector)
		fixture.process = "agent-process"
		hookForeignGuardExchange = func(string, string, time.Time, time.Time, enterprisepolicy.SessionExchange) (enterprisepolicy.GuardDecision, error) {
			return enterprisepolicy.GuardDecision{Deny: true, Reason: hookexec.ForeignHookBlockedReasonPrefix + " blocked since earlier in this session"}, nil
		}
		if held := runGuardEvent(t, fixture, connector, event, "s-1"); !strings.HasPrefix(held.ManagedRuntimeFailure, hookexec.ForeignHookBlockedReasonPrefix) {
			t.Fatalf("%s: the gateway's session block must hold: %q", connector, held.ManagedRuntimeFailure)
		}
		// The user rewrites or deletes whatever the account's home holds.
		records := filepath.Join(fixture.home, ".defenseclaw", "foreign-hook-sessions")
		fixture.write(t, enterprisepolicy.SessionPath(fixture.home, connector, "s", "s-1"),
			`{"v":1,"connector":"`+connector+`","session":"s-1","started":"2026-10-20T00:00:00Z","state":"x","blocked":false}`)
		notRunning := fmt.Errorf("dial hook socket: %w", hookexec.ErrManagedGatewayNotRunning)
		hookForeignGuardExchange = func(string, string, time.Time, time.Time, enterprisepolicy.SessionExchange) (enterprisepolicy.GuardDecision, error) {
			return enterprisepolicy.GuardDecision{}, notRunning
		}
		for _, step := range []string{"edited", "deleted"} {
			if step == "deleted" {
				if err := os.RemoveAll(records); err != nil {
					t.Fatal(err)
				}
			}
			held := runGuardEvent(t, fixture, connector, event, "s-1")
			if held.ManagedRuntimeFailure == "" {
				t.Fatalf("%s: an open outage lifted the session block after the home records were %s", connector, step)
			}
		}
	}
}

// GAP-0354: the check the standalone Hermes hook and the Amp and OpenCode
// plugins run applies the hook-time guard's outage rule. A guarded
// connector whose session exchange cannot reach the gateway is denied with
// the outage's reason (the check takes no fail mode, so unset and open
// read the same), Hermes with its block object; a gateway that answers for
// a clean session allows with the exact allow the callers accept; a host
// without the standalone summary (per-user, Secure Client) allows as before.
func TestForeignHookCheckDeniesAGuardedConnectorDuringAGatewayOutage(t *testing.T) {
	notRunning := fmt.Errorf("dial hook socket: %w", hookexec.ErrManagedGatewayNotRunning)
	connectors := map[string]string{"opencode": "tool.execute.before", "amp": "tool.call"}
	if runtime.GOOS != "windows" {
		connectors["hermes"] = "pre_tool_call"
	}
	check := func(t *testing.T, connector, event string) (foreignHookCheckResult, string) {
		t.Helper()
		var out bytes.Buffer
		payload := `{"hook_event_name":"` + event + `","session_id":"s-1"}`
		if code := runForeignHookCheck(connector, strings.NewReader(payload), &out); code != 0 {
			t.Fatalf("%s: the check always exits 0, got %d", connector, code)
		}
		var result foreignHookCheckResult
		if err := json.Unmarshal(out.Bytes(), &result); err != nil {
			t.Fatalf("%s: the answer must be JSON: %v: %q", connector, err, out.String())
		}
		return result, strings.TrimSpace(out.String())
	}
	for connector, event := range connectors {
		fixture := newPortableForeignGuardFixture(t, config.ForeignHooksRemove)
		fixture.guard(connector)
		fixture.process = "agent-process"
		exchanged := 0
		hookForeignGuardExchange = func(string, string, time.Time, time.Time, enterprisepolicy.SessionExchange) (enterprisepolicy.GuardDecision, error) {
			exchanged++
			return enterprisepolicy.GuardDecision{}, notRunning
		}
		result, _ := check(t, connector, event)
		if exchanged != 1 && !foreignHookSessionLocal(connector) {
			t.Fatalf("%s: the check did not exchange the session with the gateway (%d)", connector, exchanged)
		}
		if foreignHookSessionLocal(connector) {
			continue // Windows Amp keeps its session record locally
		}
		if !result.Deny || !strings.Contains(result.Reason, hookexec.ManagedGatewayNotRunningReason) {
			t.Fatalf("%s: a stopped gateway must deny with the not-running reason: %+v", connector, result)
		}
		// Loop round 2 review of 06bb83dd (GAP-1180): the plugins retry their
		// load-time check only on this structured flag, never on reason text.
		if !result.Retryable {
			t.Fatalf("%s: a stopped gateway with a clean scan must be a retryable denial: %+v", connector, result)
		}
		if connector == "hermes" {
			if result.HookOutput == nil || result.HookOutput.Action != "block" || !strings.HasSuffix(result.HookOutput.Message, "("+hookexec.ManagedGatewayNotRunningReason+")") {
				t.Fatalf("hermes: the outage denial must carry the Hermes block object: %+v", result.HookOutput)
			}
		} else if result.HookOutput != nil {
			t.Fatalf("%s: only Hermes gets a hook_output: %+v", connector, result.HookOutput)
		}

		// The gateway is up and the session is clean.
		hookForeignGuardExchange = func(_ string, _ string, _, _ time.Time, exchange enterprisepolicy.SessionExchange) (enterprisepolicy.GuardDecision, error) {
			return exchange.Decision, nil
		}
		if result, raw := check(t, connector, event); result.Deny || raw != `{"deny":false}` {
			t.Fatalf("%s: a clean session with the gateway up must allow exactly: %q", connector, raw)
		}

		// No standalone summary (per-user or Secure Client): unchanged allow,
		// and no exchange.
		fixture.summary = nil
		exchanged = 0
		hookForeignGuardExchange = func(string, string, time.Time, time.Time, enterprisepolicy.SessionExchange) (enterprisepolicy.GuardDecision, error) {
			exchanged++
			return enterprisepolicy.GuardDecision{}, notRunning
		}
		if result, raw := check(t, connector, event); result.Deny || raw != `{"deny":false}` || exchanged != 0 {
			t.Fatalf("%s: a host without the standalone summary must allow without an exchange: %q (%d)", connector, raw, exchanged)
		}
	}
}

// GAP-2405: when the guard's session exchange fails because the hook socket
// directory is not owned by root or the gateway account, the standalone
// Hermes hook (and the plugins) say so, in the words of the managed shell
// hooks, not that the gateway was unavailable.
func TestForeignHookCheckNamesAnUntrustedHookSocketDirectory(t *testing.T) {
	untrusted := fmt.Errorf("enterprise managed gateway peer unverified: %w: hook socket directory /opt/cisco/defenseclaw/run is not owned by root or the gateway service account", hookexec.ErrManagedHookSocketDirectoryUntrusted)
	connectors := map[string]string{"opencode": "tool.execute.before"}
	if runtime.GOOS != "windows" {
		connectors["hermes"] = "pre_tool_call"
	}
	for connector, event := range connectors {
		fixture := newPortableForeignGuardFixture(t, config.ForeignHooksRemove)
		fixture.guard(connector)
		fixture.process = "agent-process"
		hookForeignGuardExchange = func(string, string, time.Time, time.Time, enterprisepolicy.SessionExchange) (enterprisepolicy.GuardDecision, error) {
			return enterprisepolicy.GuardDecision{}, untrusted
		}
		var out bytes.Buffer
		if code := runForeignHookCheck(connector, strings.NewReader(`{"hook_event_name":"`+event+`","session_id":"s-1"}`), &out); code != 0 {
			t.Fatalf("%s: the check always exits 0, got %d", connector, code)
		}
		var result foreignHookCheckResult
		if err := json.Unmarshal(out.Bytes(), &result); err != nil {
			t.Fatalf("%s: %v: %q", connector, err, out.String())
		}
		const named = "hook socket directory is not owned by root or the gateway account"
		if !result.Deny || !strings.Contains(result.Reason, named) || strings.Contains(result.Reason, "hook record") {
			t.Fatalf("%s: an untrusted socket directory must deny and name it: %+v", connector, result)
		}
		if connector == "hermes" {
			if result.HookOutput == nil || result.HookOutput.Action != "block" || !strings.Contains(result.HookOutput.Message, named) ||
				strings.Contains(result.HookOutput.Message, hookexec.ManagedHookSocketDirectoryUntrustedReason) {
				t.Fatalf("hermes: the block object must name the directory: %+v", result.HookOutput)
			}
		}
	}
}
