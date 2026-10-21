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
	"errors"
	"fmt"
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
