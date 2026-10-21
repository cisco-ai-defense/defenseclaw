// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
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

// Re-review P1: a standalone hook in fail mode open that gets a 401 or 403
// status line followed by a body it cannot read (cut off, or over the cap)
// blocks: the status already says the credential was refused, an integrity
// failure, closed in every fail mode.
func TestStandaloneManagedAuthRefusalWithAnUnreadableBodyStaysClosed(t *testing.T) {
	original := hookAuthRetryDelay
	hookAuthRetryDelay = time.Millisecond
	t.Cleanup(func() { hookAuthRetryDelay = original })
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		for name, body := range map[string]func() io.ReadCloser{
			"truncated": func() io.ReadCloser { return io.NopCloser(&failingReader{data: []byte(`{"error":"unauth`)}) },
			"oversized": func() io.ReadCloser {
				return io.NopCloser(strings.NewReader(`{"error":"` + strings.Repeat("x", int(defaultMaxBody)+16) + `"}`))
			},
		} {
			rt := &stubRT{onRequest: func(_ *stubRT, _ *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: status, Body: body(), Header: make(http.Header)}, nil
			}}
			result := run(t, "codex", rt, func(o *Options) {
				managedCodex(o)
				o.ExplainUnenrolledAccount = true
				o.FailMode = "open"
			})
			if !blocked(result) {
				t.Fatalf("HTTP %d with a %s body allowed an open standalone call: code=%d stdout=%q stderr=%q", status, name, result.code, result.stdout, result.stderr)
			}
		}
	}
}

// failingReader returns data, then a read error: a body the gateway cut off.
type failingReader struct {
	data []byte
	done bool
}

func (r *failingReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, io.ErrUnexpectedEOF
	}
	r.done = true
	return copy(p, r.data), nil
}

// Re-review P2: a managed standalone Copilot hook whose command binds no
// reviewed Copilot event never answers allow: in every fail mode it writes
// Copilot's two native denies (preToolUse and permissionRequest, the only
// Copilot events that can block). A per-user hook keeps Copilot's documented
// fail-open result.
func TestInvalidManagedCopilotEventBindingNeverAllows(t *testing.T) {
	for _, event := range []string{"", "bogusEvent", "PreToolUse"} {
		for _, mode := range []string{"", "open", "closed"} {
			rt := ok(`{"action":"allow"}`)
			result := run(t, "copilot", rt, func(o *Options) {
				managedCodex(o)
				o.ExplainUnenrolledAccount = true
				o.Event = event
				o.FailMode = mode
			})
			if result.code != 0 || !strings.Contains(result.stdout, `"permissionDecision":"deny"`) || !strings.Contains(result.stdout, `"behavior":"deny"`) {
				t.Fatalf("event %q, fail mode %q: stdout=%q stderr=%q code=%d", event, mode, result.stdout, result.stderr, result.code)
			}
			if !strings.Contains(result.stderr, invalidManagedCopilotBindingReason) || rt.requests != 0 {
				t.Fatalf("event %q: the refusal must name its reason and never reach the gateway: stderr=%q requests=%d", event, result.stderr, rt.requests)
			}
		}
	}
	perUser := run(t, "copilot", ok(`{"action":"allow"}`), func(o *Options) { o.Event = "bogusEvent"; o.FailMode = "closed" })
	if strings.Contains(perUser.stdout, "deny") {
		t.Fatalf("a per-user hook keeps Copilot's fail-open result: stdout=%q", perUser.stdout)
	}
}

// GAP-0349 (OpenCode) and GAP-0350 (Copilot) on managed Windows, GAP-0346
// on macOS: the managed OpenCode and Copilot tool-call hooks follow the
// administrator's fail mode when the gateway service is not running, on
// every OS: unset and closed block, open allows.
func TestStandaloneManagedOpenCodeAndCopilotFollowTheAdministratorsFailMode(t *testing.T) {
	notRunning := fmt.Errorf("%w: %w", errManagedGatewayPeerUnverified, errManagedGatewayNotRunning)
	for connector, event := range map[string]string{"opencode": "tool.execute.before", "copilot": "preToolUse"} {
		for mode, wantBlock := range map[string]bool{"": true, "open": false, "closed": true} {
			result := run(t, connector, &stubRT{err: notRunning}, func(o *Options) {
				managedCodex(o)
				o.ExplainUnenrolledAccount = true
				o.Event = event
				o.FailMode = mode
				o.Stdin = strings.NewReader(`{"tool":"bash","args":{"command":"echo ok"},"toolName":"bash","toolArgs":"{}"}`)
			})
			if got := blocked(result); got != wantBlock {
				t.Fatalf("%s, fail mode %q: blocked = %v, want %v: code=%d stdout=%q stderr=%q",
					connector, mode, got, wantBlock, result.code, result.stdout, result.stderr)
			}
		}
	}
}

// Final review P2: a missing answer counts as the gateway's outage, which
// fail mode open lets through, only when the gateway contact had at least
// hookGatewayAnswerFloor of the answer budget. A slow local step (a
// foreign-hook scan close to its own budget) that leaves less fails closed,
// for the session exchange and for the hook request.
func TestStandaloneManagedNoAnswerAfterASlowLocalStepStaysClosed(t *testing.T) {
	shortAnswerBudget(t, 300*time.Millisecond)
	previousFloor := hookGatewayAnswerFloor
	hookGatewayAnswerFloor = 200 * time.Millisecond
	t.Cleanup(func() { hookGatewayAnswerFloor = previousFloor })
	addr := hungGateway(t)

	for _, tc := range []struct {
		name  string
		spent time.Duration
		open  bool
	}{
		{name: "the gateway had the budget", spent: 0, open: true},
		{name: "a local step spent the budget", spent: 250 * time.Millisecond, open: false},
	} {
		t.Run("session exchange: "+tc.name, func(t *testing.T) {
			token := "authenticated-generation-token"
			opts := Options{ManagedEnterprise: true, AuthenticatedManagedToken: &token, APIAddr: addr,
				HTTPClient: &http.Client{}, Connector: "copilot", Event: "preToolUse", FailMode: "open",
				StartedAt: time.Now().Add(-tc.spent)}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := ExchangeForeignHookSession(ctx, opts, "copilot", []byte(`{}`))
			if !errors.Is(err, errGatewayNoAnswer) {
				t.Fatalf("err = %v, want a missing answer", err)
			}
			if got := errors.Is(err, errAnswerBudgetSpentLocally); got == tc.open {
				t.Fatalf("spent locally = %v, want %v (err %v)", got, !tc.open, err)
			}
			if got := ManagedOutageFailsOpen(opts, err); got != tc.open {
				t.Fatalf("ManagedOutageFailsOpen = %v, want %v (err %v)", got, tc.open, err)
			}
		})
		t.Run("hook request: "+tc.name, func(t *testing.T) {
			started := time.Now().Add(-tc.spent)
			result := run(t, "codex", nil, func(o *Options) {
				managedCodex(o)
				o.ExplainUnenrolledAccount = true
				o.FailMode = "open"
				o.APIAddr = addr
				o.HTTPClient = &http.Client{}
				o.StartedAt = started
			})
			if blocked(result) == tc.open {
				t.Fatalf("blocked = %v, want %v: code=%d stdout=%q stderr=%q", blocked(result), !tc.open, result.code, result.stdout, result.stderr)
			}
		})
	}
}
