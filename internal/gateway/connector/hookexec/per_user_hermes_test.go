// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// rel-1-0-3 GAP-0269 (the Windows half of GAP-0150): the per-user Hermes
// hook on Windows is this native runner. Outside Secure Client it blocks a
// tool call DefenseClaw cannot check when its fail mode is closed or not set
// (the gateway is down or does not answer in time, or its answer cannot be
// used), with Hermes' block directive and a text that says why and what to
// do, and logs the call as failed closed. Only an explicit "open" lets an
// outage call run; malformed oversized input stays closed.
func TestPerUserHermesToolCallFailsClosedUnlessOpen(t *testing.T) {
	waitForDeadline := func(_ *stubRT, req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	}
	for _, tc := range []struct {
		name, want string
		rt         func() *stubRT
		timeout    time.Duration
		mutate     func(*Options)
	}{
		{name: "gateway down", want: "the DefenseClaw gateway is not running or not answering (fail mode closed)",
			rt: func() *stubRT { return &stubRT{err: errors.New("connection refused")} }},
		{name: "timeout", want: "the DefenseClaw gateway is not running or not answering (fail mode closed)",
			rt: func() *stubRT { return &stubRT{onRequest: waitForDeadline} }, timeout: 200 * time.Millisecond},
		{name: "gateway 5xx", want: "the DefenseClaw gateway is not available (fail mode closed)",
			rt: func() *stubRT { return &stubRT{status: 503, body: "unavailable"} }},
		{name: "gateway refusal", want: "the DefenseClaw gateway refused it (HTTP 401",
			rt: func() *stubRT { return &stubRT{status: 401, body: `{"error":"token rejected"}`} }},
		{name: "malformed answer", want: "returned an answer DefenseClaw could not use",
			rt: func() *stubRT { return ok("not-json") }},
		{name: "answer without an action", want: "returned an answer DefenseClaw could not use",
			rt: func() *stubRT { return ok(`{}`) }},
		{name: "unknown action", want: "returned an answer DefenseClaw could not use",
			rt: func() *stubRT { return ok(`{"action":"proceed"}`) }},
		{name: "block without directive", want: "returned an answer DefenseClaw could not use",
			rt: func() *stubRT { return ok(`{"action":"block","reason":"policy"}`) }},
		{name: "contradictory directive", want: "returned an answer DefenseClaw could not use",
			rt: func() *stubRT { return ok(`{"action":"allow","hook_output":{"decision":"block","reason":"x"}}`) }},
		{name: "oversized", want: "too large for DefenseClaw to inspect",
			rt: func() *stubRT { return ok(`{"action":"allow"}`) }, mutate: func(o *Options) { o.MaxBody = 2 }},
		{name: "missing token", want: "the DefenseClaw gateway is not available (fail mode closed)",
			rt: func() *stubRT { return ok(`{"action":"allow"}`) }, mutate: func(o *Options) {
				o.Token = ""
				o.HookDir = filepath.Join(o.Home, "no-token")
			}},
	} {
		for _, failMode := range []string{"", "closed", "open"} {
			t.Run(tc.name+" fail mode "+map[string]string{"": "unset"}[failMode]+failMode, func(t *testing.T) {
				ctx := context.Background()
				if tc.timeout > 0 {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, tc.timeout)
					defer cancel()
				}
				var home string
				result := runWithContext(t, ctx, "hermes", tc.rt(), func(o *Options) {
					// The installed per-user command binds no event.
					o.Event = ""
					o.FailMode = failMode
					o.Stdin = strings.NewReader(`{"hook_event_name":"pre_tool_call","tool_name":"terminal","tool_input":{"command":"echo x"}}`)
					if tc.mutate != nil {
						tc.mutate(o)
					}
					home = o.Home
				})
				if result.code != 0 {
					t.Fatalf("code %d, want 0 (stderr %q)", result.code, result.stderr)
				}
				logged := lastHookFailure(t, home)["fail_mode"]
				if failMode == "open" && tc.name != "oversized" && tc.name != "malformed answer" {
					if strings.TrimSpace(result.stdout) != "" {
						t.Fatalf("stdout %q, want the neutral result for an explicit open", result.stdout)
					}
					if logged != "open" {
						t.Fatalf("logged fail_mode = %q, want open", logged)
					}
					return
				}
				message := hermesBlockMessage(t, result.stdout)
				if !strings.HasPrefix(message, "DefenseClaw blocked this tool call: ") || !strings.Contains(message, tc.want) {
					t.Fatalf("message %q, want a tool-call block naming %q (stderr %q)", message, tc.want, result.stderr)
				}
				if strings.Contains(message, "administrator") {
					t.Fatalf("message %q sends a per-user account to an administrator", message)
				}
				if logged != "closed" {
					t.Fatalf("logged fail_mode = %q, want closed", logged)
				}
			})
		}
	}
}

// A per-user gateway stopped with `defenseclaw-gateway stop` is not started
// again by the hook (the Windows cold start refuses), and the block says so.
func TestPerUserHermesStoppedGatewaySaysHowToStartIt(t *testing.T) {
	refused := &stubRT{err: fmt.Errorf("dial: %w", syscall.ECONNREFUSED)}
	result := run(t, "hermes", refused, func(o *Options) {
		o.Event = ""
		o.FailMode = "closed"
		o.Stdin = strings.NewReader(`{"hook_event_name":"pre_tool_call","tool_name":"terminal"}`)
		if err := os.WriteFile(filepath.Join(o.Home, gatewayStoppedMarker), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		o.GatewayRecovery = func(context.Context, error) error { return errors.New("hook cold start skipped") }
	})
	message := hermesBlockMessage(t, result.stdout)
	if result.code != 0 || !strings.Contains(message, "was stopped with `defenseclaw-gateway stop`") {
		t.Fatalf("code %d, message %q, want the stopped-gateway block", result.code, message)
	}
}

// Hermes events that cannot block keep the neutral result. A disabled home
// leaves a registered closed hook without verified event identity, so it
// must send its native block for a possible tool call.
func TestPerUserHermesClosedKeepsNeutralResultsItCannotBlock(t *testing.T) {
	for _, tc := range []struct {
		name   string
		stdin  string
		mutate func(*Options)
	}{
		{name: "pre_llm_call", stdin: `{"hook_event_name":"pre_llm_call"}`},
		{name: "on_session_end", stdin: `{"hook_event_name":"on_session_end"}`},
		{name: "disabled home", stdin: `{"hook_event_name":"pre_tool_call"}`, mutate: func(o *Options) {
			if err := os.WriteFile(filepath.Join(o.Home, ".disabled"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := run(t, "hermes", &stubRT{err: errors.New("connection refused")}, func(o *Options) {
				o.Event = ""
				o.FailMode = "closed"
				o.Stdin = strings.NewReader(tc.stdin)
				if tc.mutate != nil {
					tc.mutate(o)
				}
			})
			blocked := strings.Contains(result.stdout, `"block"`)
			if result.code != 0 || blocked != (tc.name == "disabled home") {
				t.Fatalf("code %d, stdout %q, want block=%t", result.code, result.stdout, tc.name == "disabled home")
			}
		})
	}
}
