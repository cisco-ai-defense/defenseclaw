// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// failingBody returns its prefix and then err: a gateway that sent a status
// line and part of its answer.
type failingBody struct {
	prefix io.Reader
	err    error
}

func (b failingBody) Read(p []byte) (int, error) {
	if n, err := b.prefix.Read(p); n > 0 || !errors.Is(err, io.EOF) {
		return n, err
	}
	return 0, b.err
}

// nativeOutageBlocked reports a native hook answer that denies the call in any
// connector's native shape.
func nativeOutageBlocked(r runResult) bool {
	if r.code != 0 {
		return true
	}
	for _, marker := range []string{`"permissionDecision":"deny"`, `"decision":"block"`, `"decision":"deny"`,
		`"action":"block"`, `"permission":"deny"`, `"behavior":"deny"`, `"continue":false`} {
		if strings.Contains(r.stdout, marker) {
			return true
		}
	}
	return false
}

// oss-outage-open (owner decision 2026-10-23): the per-user native hook (the
// Windows hook of every connector) lets a call run only for a gateway outage
// and only in the outage-open tier the current config selects.
// The strict tier, strict availability, the install window, an answer the gateway gave (malformed, cut off, an error
// status, an authentication refusal) and a gateway that took the call and did
// not answer block in every tier.
func TestPerUserNativeHookOutageOpenOnlyForAnOutage(t *testing.T) {
	fastRestartRetries(t)
	type scenario struct {
		name   string
		rt     func() *stubRT
		mutate func(*Options)
		opens  bool
	}
	scenarios := []scenario{
		{name: "gateway up", rt: func() *stubRT { return ok(`{"action":"allow","raw_action":"allow"}`) }, opens: true},
		{name: "connection refused", rt: func() *stubRT { return &stubRT{err: syscall.ECONNREFUSED} }, opens: true},
		{name: "connection reset before any status", rt: func() *stubRT { return &stubRT{err: syscall.ECONNRESET} }, opens: true},
		{name: "restart outlasts the budget", rt: func() *stubRT { return &stubRT{err: syscall.ECONNREFUSED} },
			mutate: func(o *Options) { o.StartedAt = time.Now().Add(-gatewayRestartBudget + 100*time.Millisecond) }, opens: true},
		{name: "refused, strict availability", rt: func() *stubRT { return &stubRT{err: syscall.ECONNREFUSED} },
			mutate: func(o *Options) { o.StrictAvailability = true }},
		{name: "refused, install in progress", rt: func() *stubRT { return &stubRT{err: syscall.ECONNREFUSED} },
			mutate: func(o *Options) {
				if err := os.Mkdir(filepath.Join(o.Home, installLockName), 0o700); err != nil {
					panic(err)
				}
			}},
		{name: "gateway took the call and did not answer", rt: func() *stubRT {
			return &stubRT{err: fmt.Errorf("%w: %w", errGatewayTookCallNoAnswer, context.DeadlineExceeded)}
		}},
		{name: "malformed answer", rt: func() *stubRT { return ok(`{"action":"allow" garbage`) }},
		{name: "partial answer", rt: func() *stubRT {
			return &stubRT{onRequest: func(_ *stubRT, _ *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Header: make(http.Header),
					Body: io.NopCloser(failingBody{strings.NewReader(`{"action":"al`), io.ErrUnexpectedEOF})}, nil
			}}
		}},
		{name: "gateway error status", rt: func() *stubRT { return &stubRT{status: 503, body: "unavailable"} }},
		{name: "authentication refused", rt: func() *stubRT { return &stubRT{status: 401, body: "unauthorized"} }},
	}
	events := map[string]struct{ event, stdin string }{
		"claudecode":  {"PreToolUse", `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo hi"}}`},
		"codex":       {"PreToolUse", `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo hi"}}`},
		"copilot":     {"preToolUse", `{"toolName":"bash","toolArgs":{"command":"echo hi"}}`},
		"cursor":      {"beforeShellExecution", `{"hook_event_name":"beforeShellExecution","command":"echo hi"}`},
		"devin":       {"PreToolUse", `{"hook_event_name":"PreToolUse","tool_name":"exec","tool_input":{"command":"echo hi"}}`},
		"antigravity": {"PreToolUse", `{"toolName":"run_command","toolInput":{"CommandLine":"echo hi"}}`},
		"hermes":      {"pre_tool_call", `{"hook_event_name":"pre_tool_call","tool_name":"terminal","tool_input":{"command":"echo hi"}}`},
		"kiro":        {"PreToolUse", `{"hook_event_name":"PreToolUse","session_id":"s","cwd":"/work","tool_name":"execute_bash","tool_input":{"command":"echo hi"}}`},
	}
	for connector, call := range events {
		for _, tier := range []struct{ name, mode string }{{"default or permissive", "open"}, {"strict", "closed"}} {
			for _, sc := range scenarios {
				t.Run(connector+"/"+tier.name+"/"+sc.name, func(t *testing.T) {
					result := run(t, connector, sc.rt(), func(opts *Options) {
						opts.Event = call.event
						opts.Stdin = strings.NewReader(call.stdin)
						opts.FailMode = "closed"
						// The config on disk agrees with the record.
						opts.OutageFailModeNow = func() string { return tier.mode }
						if sc.mutate != nil {
							sc.mutate(opts)
						}
					})
					wantRun := sc.name == "gateway up" || (sc.opens && tier.mode == "open")
					if blocked := nativeOutageBlocked(result); blocked == wantRun {
						t.Fatalf("blocked=%v, want %v: code=%d stdout=%q stderr=%q", blocked, !wantRun, result.code, result.stdout, result.stderr)
					}
					if !wantRun || sc.name == "gateway up" {
						return
					}
					for _, want := range []string{"defenseclaw-gateway start", "defenseclaw doctor", "fail mode open for an outage"} {
						if !strings.Contains(result.stdout+result.stderr, want) {
							t.Fatalf("the outage warning does not name %q: stdout=%q stderr=%q", want, result.stdout, result.stderr)
						}
					}
				})
			}
		}
	}
}

// The config on disk (OutageFailModeNow) alone decides a classified outage.
// A prior render's outage mode cannot override it.
func TestPerUserNativeHookOutageFollowsTheConfigNow(t *testing.T) {
	fastRestartRetries(t)
	constant := func(mode string) func() string { return func() string { return mode } }
	for _, connector := range []string{"claudecode", "codex", "copilot", "cursor"} {
		for _, tc := range []struct {
			name  string
			now   func() string
			opens bool
		}{
			{"config open", constant("open"), true},
			{"strict selected since render", constant("closed"), false},
			{"config unreadable", constant(""), false},
			{"no config check", nil, false},
		} {
			t.Run(connector+"/"+tc.name, func(t *testing.T) {
				result := run(t, connector, &stubRT{err: syscall.ECONNREFUSED}, func(opts *Options) {
					opts.FailMode = "closed"
					opts.OutageFailModeNow = tc.now
				})
				if blocked := nativeOutageBlocked(result); blocked == tc.opens {
					t.Fatalf("blocked=%v, want %v: code=%d stdout=%q stderr=%q", blocked, !tc.opens, result.code, result.stdout, result.stderr)
				}
			})
		}
	}
	asked := 0
	result := run(t, "codex", &stubRT{status: 503, body: "unavailable"}, func(opts *Options) {
		opts.FailMode = "closed"
		opts.OutageFailModeNow = func() string { asked++; return "open" }
	})
	if !nativeOutageBlocked(result) || asked != 0 {
		t.Fatalf("an error status asked the config %d times or ran: code=%d stdout=%q", asked, result.code, result.stdout)
	}
}

// A managed hook ignores the per-user outage callback.
func TestManagedNativeHookIgnoresThePerUserOutageMode(t *testing.T) {
	fastRestartRetries(t)
	result := run(t, "codex", &stubRT{err: syscall.ECONNREFUSED}, func(opts *Options) {
		managedCodex(opts)
		opts.OutageFailModeNow = func() string { return "open" }
	})
	if !nativeOutageBlocked(result) {
		t.Fatalf("a managed closed hook let a refused call run: code=%d stdout=%q stderr=%q", result.code, result.stdout, result.stderr)
	}
}

// hook-post exits PerUserPostOutageExit only for a gateway that refused or
// dropped the connection before any status; a cut-off answer after a status
// line is the gateway's unusable answer.
func TestPerUserPostOutageClassifiesOnlyAnOutage(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"refused", fmt.Errorf("dial: %w", syscall.ECONNREFUSED), true},
		{"reset before any status", fmt.Errorf("read: %w", syscall.ECONNRESET), true},
		{"closed before any status", io.EOF, true},
		{"cut off after a status", fmt.Errorf("%w: %w", errPerUserAnswerIncomplete, io.ErrUnexpectedEOF), false},
		{"took the call, no answer", fmt.Errorf("%w: %w", errGatewayTookCallNoAnswer, context.DeadlineExceeded), false},
		{"timeout", context.DeadlineExceeded, false},
		{"listener unverified", errors.New("per-user gateway connected listener is unverified: owner 1001"), false},
		{"none", nil, false},
	} {
		if got := PerUserPostOutage(tc.err); got != tc.want {
			t.Errorf("%s: PerUserPostOutage = %v, want %v", tc.name, got, tc.want)
		}
	}
}
