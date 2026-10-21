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
// exchanges the session with the gateway: Copilot and OpenCode on every OS,
// Hermes on Linux and macOS.
func guardOutageConnectors() map[string]string {
	connectors := map[string]string{"opencode": "tool.execute.before", "copilot": "preToolUse"}
	if runtime.GOOS != "windows" {
		connectors["hermes"] = "pre_tool_call"
	}
	return connectors
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
