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

// A clean, fresh protected process and session record cannot authorize a
// guarded tool call while the gateway that owns the session is unavailable.
// This remains true when the administrator selected outage-only open.
func TestForeignHookGuardProtectedRecordsDoNotOpenAGatewayOutage(t *testing.T) {
	notRunning := fmt.Errorf("dial hook socket: %w", hookexec.ErrManagedGatewayNotRunning)
	for connector, event := range guardOutageConnectors() {
		t.Run(connector, func(t *testing.T) {
			fixture := newPortableForeignGuardFixture(t, config.ForeignHooksRemove)
			fixture.guard(connector)
			fixture.process = "agent-process"
			makeFreshPublishedRecords(t, connector, fixture.process, "s-1")
			hookForeignGuardExchange = func(string, string, time.Time, time.Time, enterprisepolicy.SessionExchange) (enterprisepolicy.GuardDecision, error) {
				return enterprisepolicy.GuardDecision{}, notRunning
			}
			if got := runGuardEvent(t, fixture, connector, event, "s-1"); got.ManagedRuntimeFailure != hookexec.ManagedGatewayNotRunningReason {
				t.Fatalf("fresh trusted records permitted a guarded outage call: %q", got.ManagedRuntimeFailure)
			}
		})
	}
}

// When the gateway cannot answer the session exchange (it is stopped,
// restarting or not answering) and the fail mode is not open for the
// outage (unset, closed, strict), a guarded connector's call is blocked with
// the outage's reason, and an unapproved hook the scan finds blocks with its
// own reason. Open is covered by the protected-record tests below.
func TestForeignHookGuardBlocksAGatewayOutageUnlessOpen(t *testing.T) {
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

// makeFreshPublishedRecords writes an authenticated gateway allow for both
// the process and session. The outage guard must ignore even valid records.
func makeFreshPublishedRecords(t *testing.T, connector, process, session string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "sessions")
	if err := os.Mkdir(root, 0o711); err != nil {
		t.Fatal(err)
	}
	restore := enterprisepolicy.OverridePublishedSessionKeyOwnerForTest(func(path string) (bool, error) {
		info, err := os.Lstat(path)
		if err != nil {
			return false, err
		}
		return info.Mode().IsRegular(), nil
	})
	t.Cleanup(restore)
	const identity = "4242"
	if err := enterprisepolicy.RotatePublishedSessionKey(root, identity, enterpriseForeignHookSessionKeyTrust()); err != nil {
		t.Fatal(err)
	}
	key := enterprisepolicy.SessionKey{Connector: connector, Process: process, Session: session}
	if err := enterprisepolicy.WritePublishedSessionRecordsForTest(root, identity, key, enterprisepolicy.GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got, err := enterprisepolicy.CheckPublishedForeignHookSession(root, identity, key, enterprisepolicy.GuardDecision{}, func(string) error { return nil }); err != nil || got.Deny {
		t.Fatalf("gateway records must prove a fresh allow before the outage: %+v, %v", got, err)
	}
}

// The JSON check used by Hermes and OpenCode follows the same outage block
// as native hooks even after a clean gateway allow was published.
func TestForeignHookCheckBlocksOpenOutageWithFreshRecords(t *testing.T) {
	notRunning := fmt.Errorf("dial hook socket: %w", hookexec.ErrManagedGatewayNotRunning)
	connectors := map[string]string{"opencode": "tool.execute.before"}
	if runtime.GOOS != "windows" {
		connectors["hermes"] = "pre_tool_call"
	}
	for connector, event := range connectors {
		fixture := newPortableForeignGuardFixture(t, config.ForeignHooksRemove)
		fixture.guard(connector)
		fixture.process = "agent-process"
		makeFreshPublishedRecords(t, connector, fixture.process, "s-1")
		hookForeignGuardExchange = func(string, string, time.Time, time.Time, enterprisepolicy.SessionExchange) (enterprisepolicy.GuardDecision, error) {
			return enterprisepolicy.GuardDecision{}, notRunning
		}
		var out bytes.Buffer
		runForeignHookCheck(connector, strings.NewReader(`{"hook_event_name":"`+event+`","session_id":"s-1"}`), &out)
		var result foreignHookCheckResult
		if err := json.Unmarshal(out.Bytes(), &result); err != nil {
			t.Fatalf("%s: %v: %q", connector, err, out.String())
		}
		if !result.Deny || !strings.Contains(result.Reason, hookexec.ManagedGatewayNotRunningReason) {
			t.Fatalf("%s: valid earlier records permitted the outage check: %+v", connector, result)
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
