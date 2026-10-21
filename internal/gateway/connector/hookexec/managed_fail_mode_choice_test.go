// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Owner decision 2026-10-20: a standalone managed hook follows the fail mode
// its administrator-owned runtime records. In fail mode open a call
// DefenseClaw cannot check because the gateway is down, did not answer or
// gave an unusable answer goes ahead and is logged fail-open, as on a
// per-user install. Refusals that are not an outage stay closed: a gateway
// peer DefenseClaw cannot verify, an invalid managed runtime and a missing
// token, an authentication refusal (401/403, also after the 401 retries) and
// a local event binding or contract mismatch. Strict availability still
// closes it.
func TestStandaloneManagedHookFollowsTheAdministratorsOpenFailMode(t *testing.T) {
	original := hookAuthRetryDelay
	hookAuthRetryDelay = time.Millisecond
	t.Cleanup(func() { hookAuthRetryDelay = original })
	standaloneOpen := func(opts *Options) {
		managedCodex(opts)
		opts.ExplainUnenrolledAccount = true
		opts.FailMode = "open"
	}
	for _, tc := range []struct {
		name    string
		rt      *stubRT
		mutate  func(*Options)
		blocked bool
	}{
		{name: "gateway unreachable", rt: &stubRT{err: errors.New("offline")}},
		{name: "gateway 5xx", rt: &stubRT{status: 503, body: "unavailable"}},
		{name: "malformed answer", rt: ok("not-json")},
		{name: "gateway not running", rt: &stubRT{err: fmt.Errorf("%w: %w", errManagedGatewayPeerUnverified, errManagedGatewayNotRunning)}},
		{name: "unverified gateway peer", rt: &stubRT{err: errManagedGatewayPeerUnverified}, blocked: true},
		{name: "invalid managed runtime", rt: ok(`{"action":"allow"}`), blocked: true,
			mutate: func(o *Options) { o.ManagedRuntimeFailure = "enterprise_managed_runtime_state_invalid" }},
		{name: "strict availability", rt: &stubRT{err: errors.New("offline")}, blocked: true,
			mutate: func(o *Options) { o.StrictAvailability = true }},
		{name: "gateway 401 after retries", rt: &stubRT{status: 401, body: `{"error":"unauthorized"}`}, blocked: true},
		{name: "gateway 403", rt: &stubRT{status: 403, body: `{"error":"forbidden"}`}, blocked: true},
		{name: "codex contract missing", rt: ok(`{"action":"allow"}`), blocked: true,
			mutate: func(o *Options) { o.HookContractID = "" }},
		{name: "codex event mismatch", rt: ok(`{"action":"allow"}`), blocked: true,
			mutate: func(o *Options) { o.Stdin = strings.NewReader(`{"hook_event_name":"PostToolUse"}`) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := run(t, "codex", tc.rt, func(o *Options) {
				standaloneOpen(o)
				if tc.mutate != nil {
					tc.mutate(o)
				}
			})
			if blocked(result) != tc.blocked {
				t.Fatalf("blocked = %v, want %v: code=%d stdout=%q stderr=%q", blocked(result), tc.blocked, result.code, result.stdout, result.stderr)
			}
		})
	}
	// The same hook in fail mode closed, the default, blocks an outage.
	closed := run(t, "codex", &stubRT{err: errors.New("offline")}, func(o *Options) {
		standaloneOpen(o)
		o.FailMode = "closed"
	})
	if !blocked(closed) {
		t.Fatalf("closed standalone hook allowed an outage: code=%d stdout=%q", closed.code, closed.stdout)
	}
}

// A standalone Hermes hook in fail mode open lets a tool call through on an
// outage instead of the managed block directive; closed blocks it.
func TestStandaloneManagedHermesFollowsTheAdministratorsFailMode(t *testing.T) {
	for mode, wantBlock := range map[string]bool{"open": false, "closed": true} {
		result := run(t, "hermes", &stubRT{err: errors.New("offline")}, func(o *Options) {
			o.Event = "pre_tool_call"
			o.FailMode = mode
			o.ManagedEnterprise = true
			o.ExplainUnenrolledAccount = true
		})
		if got := blocked(result); got != wantBlock {
			t.Fatalf("fail mode %s: blocked = %v, want %v: stdout=%q stderr=%q", mode, got, wantBlock, result.stdout, result.stderr)
		}
	}
}

// GAP-0346: a managed standalone GitHub Copilot hook follows the
// administrator's fail mode when its gateway service is not running: unset
// and closed block the tool call and the permission request with Copilot's
// native deny, open allows them. An unapproved hook the foreign-hook guard
// found, and an invalid managed runtime, block in fail mode open too.
func TestStandaloneManagedCopilotFollowsTheAdministratorsFailMode(t *testing.T) {
	notRunning := fmt.Errorf("%w: %w", errManagedGatewayPeerUnverified, errManagedGatewayNotRunning)
	for _, event := range []string{"preToolUse", "permissionRequest"} {
		for _, tc := range []struct {
			mode    string
			failure string
			blocked bool
		}{
			{mode: "", blocked: true},
			{mode: "open"},
			{mode: "closed", blocked: true},
			{mode: "open", failure: ForeignHookBlockedReasonPrefix + " your organization blocks copilot hooks it has not approved", blocked: true},
			{mode: "open", failure: "enterprise_managed_runtime_state_invalid", blocked: true},
		} {
			result := run(t, "copilot", &stubRT{err: notRunning}, func(o *Options) {
				managedCodex(o)
				o.ExplainUnenrolledAccount = true
				o.Event = event
				o.FailMode = tc.mode
				o.ManagedRuntimeFailure = tc.failure
				o.Stdin = strings.NewReader(`{"toolName":"bash","toolArgs":"{\"command\":\"echo ok\"}"}`)
			})
			if got := blocked(result); got != tc.blocked {
				t.Fatalf("%s, fail mode %q, runtime failure %q: blocked = %v, want %v: stdout=%q stderr=%q",
					event, tc.mode, tc.failure, got, tc.blocked, result.stdout, result.stderr)
			}
			if !tc.blocked && !strings.Contains(result.stderr, "allowing") {
				t.Fatalf("%s: an open outage must say the call is allowed: stderr=%q", event, result.stderr)
			}
		}
	}
}

// GAP-0346: only an outage of a standalone hook in fail mode open lets the
// call through when the foreign-hook guard cannot reach the gateway.
func TestManagedOutageFailsOpenOnlyForAnOpenStandaloneOutage(t *testing.T) {
	notRunning := fmt.Errorf("dial hook socket: %w", errManagedGatewayNotRunning)
	for _, tc := range []struct {
		name   string
		mutate func(*Options)
		err    error
		want   bool
	}{
		{name: "unset", mutate: func(o *Options) { o.FailMode = "" }, err: notRunning},
		{name: "closed", mutate: func(o *Options) { o.FailMode = "closed" }, err: notRunning},
		{name: "open, not running", err: notRunning, want: true},
		{name: "open, restarting", err: fmt.Errorf("session exchange: %w", errGatewayRestarting), want: true},
		{name: "open, no answer", err: fmt.Errorf("session exchange: %w", errGatewayNoAnswer), want: true},
		{name: "open, port held", err: fmt.Errorf("%w: %w", errManagedGatewayPortHeld, errManagedGatewayNotRunning)},
		{name: "open, unverified peer", err: errManagedGatewayPeerUnverified},
		{name: "open, unusable answer", err: errors.New("invalid session gateway decision")},
		{name: "open, no error"},
		{name: "open, strict availability", mutate: func(o *Options) { o.StrictAvailability = true }, err: notRunning},
		{name: "open, runtime failure", mutate: func(o *Options) { o.ManagedRuntimeFailure = "enterprise_managed_runtime_state_invalid" }, err: notRunning},
		{name: "open, Secure Client", mutate: func(o *Options) { o.SecureClient = true }, err: notRunning},
		{name: "open, per-user", mutate: func(o *Options) { o.ManagedEnterprise = false }, err: notRunning},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := Options{Connector: "copilot", ManagedEnterprise: true, ExplainUnenrolledAccount: true, FailMode: "open"}
			if tc.mutate != nil {
				tc.mutate(&opts)
			}
			if got := ManagedOutageFailsOpen(opts, tc.err); got != tc.want {
				t.Fatalf("ManagedOutageFailsOpen = %v, want %v", got, tc.want)
			}
		})
	}
}
