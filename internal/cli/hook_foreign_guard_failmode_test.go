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
	"errors"
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

// GAP-0346: on a standalone host the foreign-hook guard's session exchange
// meets a stopped gateway before the hook request does. Status reported the
// administrator's open for managed Copilot, yet the guard blocked every call
// as closed. Now unset and closed still block with the not-running reason,
// open lets the call go on to the hook request (which gives the open result),
// and an unapproved hook the scan finds blocks in every fail mode.
func TestForeignHookGuardFollowsTheFailModeOnAGatewayOutage(t *testing.T) {
	notRunning := fmt.Errorf("dial hook socket: %w", hookexec.ErrManagedGatewayNotRunning)
	for _, tc := range []struct {
		mode    string
		strict  bool
		blocked bool
	}{
		{mode: "closed", strict: true, blocked: true}, // unset resolves closed + strict (buildHookOptionsForRuntime)
		{mode: "open"},
		{mode: "closed", strict: true, blocked: true},
		{mode: "open", strict: true, blocked: true}, // DEFENSECLAW_STRICT_AVAILABILITY=1
	} {
		fixture := newPortableForeignGuardFixture(t, config.ForeignHooksRemove)
		fixture.guard("copilot")
		fixture.process = "agent-process"
		exchangeOpts := hookexec.Options{Connector: "copilot", ManagedEnterprise: true, ExplainUnenrolledAccount: true,
			FailMode: tc.mode, StrictAvailability: tc.strict}
		hookForeignGuardExchange = func(string, string, time.Time, time.Time, enterprisepolicy.SessionExchange) (enterprisepolicy.GuardDecision, error) {
			return enterprisepolicy.GuardDecision{}, foreignHookSessionExchangeError(exchangeOpts, notRunning)
		}
		got := fixture.runEvent(t, "copilot", "preToolUse", "sessionId", "s-1")
		if tc.blocked && got.ManagedRuntimeFailure != hookexec.ManagedGatewayNotRunningReason {
			t.Fatalf("mode %s strict %v: a stopped gateway must block with the not-running reason: %q", tc.mode, tc.strict, got.ManagedRuntimeFailure)
		}
		if !tc.blocked && got.ManagedRuntimeFailure != "" {
			t.Fatalf("mode open: a stopped gateway must leave the call to the hook's open result, got %q", got.ManagedRuntimeFailure)
		}

		// An unapproved hook the scan finds blocks whatever the fail mode.
		foreign := filepath.Join(fixture.project, ".github", "hooks", "x.json")
		fixture.write(t, foreign, `{"hooks": {"preToolUse": [{"bash": "./rewrite.sh"}]}}`)
		found := fixture.runEvent(t, "copilot", "preToolUse", "sessionId", "s-1")
		if !strings.HasPrefix(found.ManagedRuntimeFailure, hookexec.ForeignHookBlockedReasonPrefix) || !strings.Contains(found.ManagedRuntimeFailure, foreign) {
			t.Fatalf("mode %s: an unapproved hook must block in every fail mode: %q", tc.mode, found.ManagedRuntimeFailure)
		}
	}
}

// The exchange error is marked for the open outage only.
func TestForeignHookSessionExchangeErrorMarksOnlyAnOpenOutage(t *testing.T) {
	notRunning := fmt.Errorf("dial hook socket: %w", hookexec.ErrManagedGatewayNotRunning)
	open := hookexec.Options{Connector: "copilot", ManagedEnterprise: true, ExplainUnenrolledAccount: true, FailMode: "open"}
	if err := foreignHookSessionExchangeError(open, notRunning); !errors.Is(err, errForeignHookSessionOutageOpen) || !hookexec.ManagedGatewayNotRunning(err) {
		t.Fatalf("open outage: %v", err)
	}
	closed := open
	closed.FailMode = "closed"
	if err := foreignHookSessionExchangeError(closed, notRunning); errors.Is(err, errForeignHookSessionOutageOpen) || err != notRunning {
		t.Fatalf("closed outage must keep its error: %v", err)
	}
	if err := foreignHookSessionExchangeError(open, errors.New("invalid session gateway decision")); errors.Is(err, errForeignHookSessionOutageOpen) {
		t.Fatalf("a non-outage error must not be marked: %v", err)
	}
}

// GAP-0349 and GAP-0350 (managed Windows), GAP-0346 (macOS): the guard
// runs before the hook request for every guarded connector, OpenCode's
// tool.execute.before included. Unset and closed still block a stopped
// gateway; open leaves the call to the hook's open result.
func TestForeignHookGuardFollowsTheFailModeForOpenCodeAndCopilot(t *testing.T) {
	notRunning := fmt.Errorf("dial hook socket: %w", hookexec.ErrManagedGatewayNotRunning)
	for connector, event := range map[string]string{"opencode": "tool.execute.before", "copilot": "preToolUse"} {
		for _, tc := range []struct {
			mode    string
			strict  bool
			blocked bool
		}{
			{mode: "closed", strict: true, blocked: true}, // unset
			{mode: "open"},
			{mode: "closed", strict: true, blocked: true},
		} {
			fixture := newPortableForeignGuardFixture(t, config.ForeignHooksRemove)
			fixture.guard(connector)
			fixture.process = "agent-process"
			exchangeOpts := hookexec.Options{Connector: connector, ManagedEnterprise: true, ExplainUnenrolledAccount: true,
				FailMode: tc.mode, StrictAvailability: tc.strict}
			hookForeignGuardExchange = func(string, string, time.Time, time.Time, enterprisepolicy.SessionExchange) (enterprisepolicy.GuardDecision, error) {
				return enterprisepolicy.GuardDecision{}, foreignHookSessionExchangeError(exchangeOpts, notRunning)
			}
			payload, err := json.Marshal(map[string]any{"hook_event_name": event, "cwd": filepath.Join(fixture.project, "src"), "session_id": "s-1", "sessionId": "s-1"})
			if err != nil {
				t.Fatal(err)
			}
			opts := hookexec.Options{Connector: connector, Event: event, ManagedEnterprise: true, Stdin: bytes.NewReader(payload), Stderr: io.Discard}
			applyEnterpriseForeignHookGuard(&opts)
			if tc.blocked && opts.ManagedRuntimeFailure != hookexec.ManagedGatewayNotRunningReason {
				t.Fatalf("%s mode %s: a stopped gateway must block with the not-running reason: %q", connector, tc.mode, opts.ManagedRuntimeFailure)
			}
			if !tc.blocked && opts.ManagedRuntimeFailure != "" {
				t.Fatalf("%s mode open: the call must go on to the hook's open result, got %q", connector, opts.ManagedRuntimeFailure)
			}
		}
	}
}

// Final review P1: a session the gateway blocked at its start (an unapproved
// hook, since deleted while the agent still runs it) stays blocked when the
// gateway then stops and the administrator chose open. The hook mirrors the
// gateway's session block under the account's home and consults it before
// an open outage allows a clean scan; a copy it cannot read blocks too.
func TestForeignHookGuardKeepsAGatewaySessionBlockThroughAnOpenOutage(t *testing.T) {
	fixture := newPortableForeignGuardFixture(t, config.ForeignHooksRemove)
	fixture.guard("copilot")
	fixture.process = "agent-process"
	foreign := filepath.Join(fixture.project, ".github", "hooks", "x.json")
	fixture.write(t, foreign, `{"hooks": {"preToolUse": [{"bash": "./rewrite.sh"}]}}`)
	isBlock := func(o hookexec.Options) bool {
		return strings.HasPrefix(o.ManagedRuntimeFailure, hookexec.ForeignHookBlockedReasonPrefix)
	}
	if start := fixture.runEvent(t, "copilot", "sessionStart", "sessionId", "s-1"); !isBlock(start) {
		t.Fatalf("a session start with an unapproved hook must block: %q", start.ManagedRuntimeFailure)
	}
	if err := os.Remove(foreign); err != nil {
		t.Fatal(err)
	}
	if held := fixture.runEvent(t, "copilot", "preToolUse", "sessionId", "s-1"); !isBlock(held) {
		t.Fatalf("the gateway must keep the session blocked: %q", held.ManagedRuntimeFailure)
	}

	exchangeOpts := hookexec.Options{Connector: "copilot", ManagedEnterprise: true, ExplainUnenrolledAccount: true, FailMode: "open"}
	notRunning := fmt.Errorf("dial hook socket: %w", hookexec.ErrManagedGatewayNotRunning)
	hookForeignGuardExchange = func(string, string, time.Time, time.Time, enterprisepolicy.SessionExchange) (enterprisepolicy.GuardDecision, error) {
		return enterprisepolicy.GuardDecision{}, foreignHookSessionExchangeError(exchangeOpts, notRunning)
	}
	if held := fixture.runEvent(t, "copilot", "preToolUse", "sessionId", "s-1"); !isBlock(held) || !strings.Contains(held.ManagedRuntimeFailure, foreign) {
		t.Fatalf("an open outage lifted the session block: %q", held.ManagedRuntimeFailure)
	}
	// Another agent process and session have no block: the open outage
	// lets their clean scan through.
	fixture.process = "agent-process-2"
	if fresh := fixture.runEvent(t, "copilot", "preToolUse", "sessionId", "s-2"); fresh.ManagedRuntimeFailure != "" {
		t.Fatalf("a clean session must follow the open fail mode: %q", fresh.ManagedRuntimeFailure)
	}
	// A copy that cannot be read blocks.
	fixture.process = "agent-process-3"
	fixture.write(t, enterprisepolicy.SessionPath(fixture.home, "copilot", "s", "s-3"), "{")
	if unreadable := fixture.runEvent(t, "copilot", "preToolUse", "sessionId", "s-3"); !isBlock(unreadable) {
		t.Fatalf("an unreadable session copy must block: %q", unreadable.ManagedRuntimeFailure)
	}
}
