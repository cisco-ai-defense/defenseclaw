// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A Unix standalone managed hook that fails closed says, in one line that
// starts with DefenseClaw, what it blocked (a prompt is not a tool call),
// why and what to do, with the internal reason code last in parentheses.
// Claude Code shows this stderr line as the block message; Codex, Devin and
// Cursor show the reason in their block body.
func TestManagedStandaloneFailClosedTextIsPlain(t *testing.T) {
	const unavailable = "the DefenseClaw gateway is not available. Try again in a moment; if this continues, contact your administrator."
	for _, tc := range []struct {
		name    string
		failure sessionStopCause
		ev      sessionStopEvent
		want    string
		body    bool
	}{
		{
			name:    "claude prompt, gateway unreachable",
			failure: sessionStopCauses[2],
			ev:      sessionStopEvent{connector: "claudecode", payload: `{"hook_event_name":"UserPromptSubmit"}`},
			want:    "DefenseClaw blocked this prompt: " + unavailable,
		},
		{
			name:    "codex prompt, gateway unreachable",
			failure: sessionStopCauses[2],
			ev:      sessionStopEvent{connector: "codex", event: "UserPromptSubmit"},
			want:    "DefenseClaw blocked this prompt: " + unavailable,
			body:    true,
		},
	} {
		r, _ := runSessionStop(t, tc.failure, tc.ev, true)
		if tc.ev.connector == "claudecode" {
			if r.code != 0 || !strings.Contains(r.stdout, mustJSONString(tc.want)) || r.stderr != "" {
				t.Fatalf("%s: expected structured prompt block: %+v", tc.name, r)
			}
		} else if got := strings.TrimSpace(r.stderr); got != tc.want {
			t.Fatalf("%s: stderr\n got %q\nwant %q", tc.name, got, tc.want)
		}
		if tc.body && !strings.Contains(r.stdout, mustJSONString(tc.want)) {
			t.Fatalf("%s: block body must carry the same text: %q", tc.name, r.stdout)
		}
		if strings.Contains(r.stderr, "claude-code tool") || strings.Contains(r.stderr, "token drift") {
			t.Fatalf("%s: internal wording leaked: %q", tc.name, r.stderr)
		}
	}
}

// Outside the standalone profile (Secure Client and every other managed
// hook) the fail-closed text is unchanged.
func TestManagedFailClosedTextOutsideStandaloneIsUnchanged(t *testing.T) {
	r, _ := runSessionStop(t, sessionStopCauses[0],
		sessionStopEvent{connector: "claudecode", payload: `{"hook_event_name":"UserPromptSubmit"}`}, false)
	if want := "defenseclaw: gateway unreachable, blocking claude-code tool (fail mode closed): enterprise_managed_hook_socket_missing"; strings.TrimSpace(r.stderr) != want {
		t.Fatalf("stderr = %q, want %q", r.stderr, want)
	}
	r, _ = runSessionStop(t, sessionStopCauses[0],
		sessionStopEvent{connector: "codex", event: "UserPromptSubmit"}, false)
	if want := `{"decision":"block","reason":"DefenseClaw hook failed closed"}`; strings.TrimSpace(r.stdout) != want {
		t.Fatalf("stdout = %q, want %q", r.stdout, want)
	}
}

func TestHookEventSubject(t *testing.T) {
	for event, want := range map[string]string{
		"beforeSubmitPrompt":  "prompt",
		"tool.execute.before": "tool call",
		"PostToolUse":         "tool result",
		"PreCompact":          "PreCompact event",
		"":                    "request",
	} {
		if got := hookEventSubject(event); got != want {
			t.Fatalf("hookEventSubject(%q) = %q, want %q", event, got, want)
		}
	}
}

type notRunningRT struct{}

func (notRunningRT) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("%w: %w (state=1 pid=0)", errManagedGatewayPeerUnverified, errManagedGatewayNotRunning)
}

type portHeldRT struct{}

func (portHeldRT) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("%w: %w: connected listener PID 9328 does not equal service PID 7828",
		errManagedGatewayPeerUnverified, errManagedGatewayPortHeld)
}

// GAP-1029: while another process listens on the gateway API port, a Windows
// standalone hook says the port is held, not that the running service is
// stopped; Secure Client keeps the peer-unverified reason.
func TestWindowsStandaloneHeldAPIPortFailsClosedNamingThePort(t *testing.T) {
	for _, explain := range []bool{true, false} {
		home := t.TempDir()
		token := "managed-test-token"
		var out, errb bytes.Buffer
		Run(context.Background(), Options{
			Connector: "codex", Event: "PreToolUse", HookContractID: "codex-hooks-v4", APIAddr: "127.0.0.1:1",
			Home: home, HookDir: filepath.Join(home, "hooks"), FailMode: "open", ManagedEnterprise: true,
			ExplainUnenrolledAccount: explain, AuthenticatedManagedToken: &token,
			Stdin:  strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"shell"}`),
			Stdout: &out, Stderr: &errb, HTTPClient: &http.Client{Transport: portHeldRT{}},
		})
		failures, _ := os.ReadFile(filepath.Join(home, "logs", "hook-failures.jsonl"))
		held := strings.Contains(out.String(), "another program is using the DefenseClaw gateway") &&
			strings.Contains(string(failures), managedGatewayPortHeldReason)
		if explain != held || strings.Contains(out.String(), "not running") {
			t.Fatalf("explain=%v: stdout = %q failures = %q, want the held-port text only for the standalone hook", explain, out.String(), failures)
		}
	}
}

// A Windows standalone managed hook (ExplainUnenrolledAccount) whose gateway
// service is stopped fails closed with the plain text and says the service
// is not running, in the agent's denial and in hook-failures.jsonl
// (GAP-0013). Secure Client keeps the peer-unverified reason and the
// generic text.
func TestWindowsStandaloneStoppedGatewayFailsClosedWithAPlainReason(t *testing.T) {
	run := func(explain bool) (int, string, string, string) {
		home := t.TempDir()
		token := "managed-test-token"
		var out, errb bytes.Buffer
		code := Run(context.Background(), Options{
			Connector:                 "codex",
			Event:                     "PreToolUse",
			HookContractID:            "codex-hooks-v4",
			APIAddr:                   "127.0.0.1:1",
			Home:                      home,
			HookDir:                   filepath.Join(home, "hooks"),
			FailMode:                  "open",
			ManagedEnterprise:         true,
			ExplainUnenrolledAccount:  explain,
			AuthenticatedManagedToken: &token,
			Stdin:                     strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"shell"}`),
			Stdout:                    &out,
			Stderr:                    &errb,
			HTTPClient:                &http.Client{Transport: notRunningRT{}},
		})
		failures, _ := os.ReadFile(filepath.Join(home, "logs", "hook-failures.jsonl"))
		return code, out.String(), errb.String(), string(failures)
	}
	code, stdout, stderr, failures := run(true)
	want := "DefenseClaw blocked this tool call: the DefenseClaw gateway service is not running on this computer. " +
		"Try again in a moment; if this continues, ask your administrator to check DefenseClaw on this computer: `enterprise windows status` names what to do."
	if code != 0 || !strings.Contains(stdout, `"permissionDecision":"deny"`) || !strings.Contains(stdout, mustJSONString(want)) {
		t.Fatalf("windows standalone: code = %d stdout = %q stderr = %q, want a deny carrying %q", code, stdout, stderr, want)
	}
	if !strings.Contains(failures, managedGatewayNotRunningReason) {
		t.Fatalf("hook-failures.jsonl = %q, want %s", failures, managedGatewayNotRunningReason)
	}
	_, stdout, _, failures = run(false)
	if !strings.Contains(stdout, failedClosed) || !strings.Contains(failures, managedGatewayPeerUnverifiedReason) {
		t.Fatalf("secure client: stdout = %q failures = %q, want the unchanged text and reason", stdout, failures)
	}
}

// A Windows standalone Cursor hook whose gateway service is stopped is
// refused by the foreign-hook guard before hookexec reads the payload, and
// Cursor's command binds no event. The deny must still be the event's own
// (permission deny on preToolUse and beforeShellExecution), not the {}
// Cursor answers an event it cannot name with: Cursor ran the shell call of
// an open session (GAP-1032). Secure Client is unchanged.
func TestWindowsStandaloneCursorStoppedGatewayDeniesEachToolEvent(t *testing.T) {
	for _, event := range []string{"preToolUse", "beforeShellExecution"} {
		run := func(explain bool) (int, string) {
			home := t.TempDir()
			var out, errb bytes.Buffer
			code := Run(context.Background(), Options{
				Connector:                "cursor",
				Home:                     home,
				HookDir:                  filepath.Join(home, "hooks"),
				ManagedEnterprise:        true,
				ExplainUnenrolledAccount: explain,
				ManagedRuntimeFailure:    managedGatewayNotRunningReason,
				Stdin:                    strings.NewReader(`{"hook_event_name":"` + event + `","command":"Get-Date"}`),
				Stdout:                   &out,
				Stderr:                   &errb,
			})
			return code, out.String()
		}
		code, stdout := run(true)
		if code != blockExit || !strings.Contains(stdout, `"permission":"deny"`) ||
			!strings.Contains(stdout, "DefenseClaw blocked this tool call: the DefenseClaw gateway service is not running") {
			t.Fatalf("%s: code = %d stdout = %q, want the event's deny with the plain text", event, code, stdout)
		}
		if code, stdout = run(false); strings.TrimSpace(stdout) != "{}" || code != blockExit {
			t.Fatalf("%s: Secure Client code = %d stdout = %q, want its unchanged answer", event, code, stdout)
		}
	}
}

// A standalone hook that refuses an over-cap Claude Code prompt shows the
// structured prompt block (not a raw stderr line about a "request") and
// reports the refusal to the gateway with the event and session fields and
// none of the content, so it has an audit record (GAP-0965, GAP-1042).
func TestManagedStandaloneOversizedPromptIsBlockedAndReported(t *testing.T) {
	rt := &stubRT{status: http.StatusOK, body: `{"action":"block"}`}
	prompt := strings.Repeat("p", 4096)
	r := run(t, "claudecode", rt, func(o *Options) {
		o.Event = ""
		o.ManagedEnterprise, o.ManagedStandalone = true, true
		o.ManagedUnixSocket, o.ManagedServiceUID = "/run/defenseclaw-hook/hook.sock", 0
		o.FailMode, o.MaxBody = "closed", 1024
		o.Stdin = strings.NewReader(`{"session_id":"sess-1","hook_event_name":"UserPromptSubmit","prompt":"` + prompt + `"}`)
	})
	want := mustJSONString("DefenseClaw blocked this prompt: it is too large for DefenseClaw to inspect. Make it smaller and try again.")
	if r.code != 0 || !strings.Contains(r.stdout, `"decision":"block"`) || !strings.Contains(r.stdout, want) || r.stderr != "" {
		t.Fatalf("refusal = %+v, want the structured prompt block", r)
	}
	if rt.requests != 1 || rt.gotReq.Header.Get(HookRefusalHeader) != HookRefusalPayloadTooLarge ||
		!strings.Contains(string(rt.gotBody), `"session_id":"sess-1"`) || strings.Contains(string(rt.gotBody), "ppp") {
		t.Fatalf("report: %d request(s), body %q", rt.requests, rt.gotBody)
	}
}

// A newly enrolled Windows standalone account can meet a 401 on its first
// call while the guardian's authorization ledger catches up: the hook sends
// the call again and it is served. A 401 that stays fails closed with the
// plain text and no operator-only advice a standard user cannot follow
// (GAP-0680).
func TestWindowsStandaloneFirstCallRetriesA401WithoutOperatorAdvice(t *testing.T) {
	original := hookAuthRetryDelay
	hookAuthRetryDelay = time.Millisecond
	t.Cleanup(func() { hookAuthRetryDelay = original })
	managed := func(opts *Options) {
		token := "managed-test-token"
		opts.ManagedEnterprise = true
		opts.ExplainUnenrolledAccount = true
		opts.AuthenticatedManagedToken = &token
		opts.FailMode = "closed"
	}
	answers := []int{http.StatusUnauthorized, http.StatusOK}
	rt := &stubRT{onRequest: func(s *stubRT, _ *http.Request) (*http.Response, error) {
		status := answers[min(s.requests, len(answers))-1]
		return &http.Response{StatusCode: status, Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader(`{"action":"allow"}`))}, nil
	}}
	if r := run(t, "codex", rt, managed); r.code != 0 || rt.requests != 2 || strings.Contains(r.stdout, "deny") {
		t.Fatalf("first call: code %d after %d request(s), stdout %q", r.code, rt.requests, r.stdout)
	}
	refused := &stubRT{status: http.StatusUnauthorized, body: `{"error":"unauthorized"}`}
	r := run(t, "codex", refused, managed)
	if refused.requests != 1+hookAuthRetries || !strings.Contains(r.stdout, `"permissionDecision":"deny"`) {
		t.Fatalf("lasting 401: %d request(s), stdout %q", refused.requests, r.stdout)
	}
	for _, leaked := range []string{"token drift", "doctor --fix", "defenseclaw-gateway restart"} {
		if strings.Contains(r.stdout+r.stderr, leaked) {
			t.Fatalf("a standard user sees operator advice %q: %q", leaked, r.stdout+r.stderr)
		}
	}
}
