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
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"
	"testing"
	"time"
)

// GAP-0094, GAP-0102, GAP-0107: a per-user hook whose own gateway restarts
// (defenseclaw-gateway restart, an upgrade) is answered by the gateway that
// comes up, from its policy, instead of failing or waiting out the restart.
func TestPerUserHookIsAnsweredByTheGatewayThatRestarts(t *testing.T) {
	fastRestartRetries(t)
	for _, test := range []struct {
		name string
		err  error
	}{
		{"connection refused", syscall.ECONNREFUSED},
		{"connection dropped unanswered", io.EOF},
		{"connection reset", syscall.ECONNRESET},
	} {
		t.Run(test.name, func(t *testing.T) {
			closed := func(opts *Options) { opts.FailMode = "closed" }
			allowed := run(t, "codex", failingThen(3, test.err, `{"action":"allow"}`), closed)
			if allowed.code != 0 || allowed.rt.requests != 4 || strings.Contains(allowed.stdout, "deny") {
				t.Fatalf("allow after restart: code=%d requests=%d stdout=%q stderr=%q",
					allowed.code, allowed.rt.requests, allowed.stdout, allowed.stderr)
			}
			denied := run(t, "codex", failingThen(2, test.err, `{"action":"block","reason":"marker rule"}`), closed)
			if denied.rt.requests != 3 || !strings.Contains(denied.stdout+denied.stderr, "marker rule") {
				t.Fatalf("policy deny after restart: code=%d requests=%d stdout=%q stderr=%q",
					denied.code, denied.rt.requests, denied.stdout, denied.stderr)
			}
		})
	}
}

// A restart or outage longer than the budget blocks the call within it, with
// the restart named, and never allows it (fail mode closed, the default of
// an action-mode connector).
func TestPerUserHookBlocksWhenTheRestartOutlastsTheBudget(t *testing.T) {
	fastRestartRetries(t)
	for _, connector := range []string{"codex", "claudecode"} {
		t.Run(connector, func(t *testing.T) {
			started := time.Now()
			result := run(t, connector, &stubRT{err: syscall.ECONNREFUSED}, func(opts *Options) {
				opts.FailMode = "closed"
				opts.StartedAt = time.Now().Add(-gatewayRestartBudget + 150*time.Millisecond)
			})
			if elapsed := time.Since(started); elapsed > time.Second {
				t.Fatalf("the hook waited %s past its restart budget", elapsed)
			}
			if result.rt.requests < 2 {
				t.Fatalf("requests = %d, want the call sent again within the budget", result.rt.requests)
			}
			blocked := result.code == 2 || strings.Contains(result.stdout, `"permissionDecision":"deny"`)
			if !blocked {
				t.Fatalf("an unanswered per-user call was not blocked: code=%d stdout=%q", result.code, result.stdout)
			}
			if !strings.Contains(result.stdout+result.stderr, "restarting or not running") {
				t.Fatalf("stdout=%q stderr=%q, want the restart named", result.stdout, result.stderr)
			}
		})
	}
}

// An older per-user open preference closes when the restart budget ends,
// with a reason that names the restart.
func TestPerUserOpenHookBlocksAndNamesTheRestart(t *testing.T) {
	fastRestartRetries(t)
	result := run(t, "claudecode", &stubRT{err: syscall.ECONNREFUSED}, func(opts *Options) {
		opts.StartedAt = time.Now().Add(-gatewayRestartBudget + 150*time.Millisecond)
	})
	if !blocked(result) || !strings.Contains(result.stdout+result.stderr, "restarting or not running") {
		t.Fatalf("code=%d stdout=%q stderr=%q, want a restart block", result.code, result.stdout, result.stderr)
	}
}

// reservedLoopbackAddr returns a loopback address nobody listens on.
func reservedLoopbackAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

// The real transport (Linux, macOS, Windows): a gateway that comes back on
// its port within the budget answers the call.
func TestPerUserHookAnswersFromAGatewayThatComesBackOnItsPort(t *testing.T) {
	addr := reservedLoopbackAddr(t)
	served := make(chan struct{})
	go func() {
		time.Sleep(500 * time.Millisecond)
		var listener net.Listener
		for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
			var err error
			if listener, err = net.Listen("tcp", addr); err == nil {
				break
			}
		}
		close(served)
		if listener == nil {
			return
		}
		server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"action":"allow"}`)
		}), ReadHeaderTimeout: time.Second}
		t.Cleanup(func() { _ = server.Close() })
		_ = server.Serve(listener)
	}()
	started := time.Now()
	result := run(t, "codex", &stubRT{}, func(opts *Options) {
		opts.APIAddr = addr
		opts.HTTPClient = nil
		opts.FailMode = "closed"
	})
	<-served
	if elapsed := time.Since(started); elapsed > gatewayRestartBudget+time.Second {
		t.Fatalf("the call took %s", elapsed)
	}
	if result.code != 0 || strings.Contains(result.stdout, "deny") {
		t.Fatalf("code=%d stdout=%q stderr=%q, want the answer of the gateway that came back", result.code, result.stdout, result.stderr)
	}
}

// The real transport: nothing listens on the port for the whole budget. The
// call is blocked within about the budget (a connect to a closed port takes
// about 2 s on Windows, and a try still connecting at the end is ended).
func TestPerUserHookBlocksWithinTheBudgetWhenNothingListens(t *testing.T) {
	addr := reservedLoopbackAddr(t)
	started := time.Now()
	result := run(t, "codex", &stubRT{}, func(opts *Options) {
		opts.APIAddr = addr
		opts.HTTPClient = nil
		opts.FailMode = "closed"
	})
	elapsed := time.Since(started)
	if elapsed < gatewayRestartBudget-time.Second || elapsed > gatewayRestartBudget+1500*time.Millisecond {
		t.Fatalf("the call was blocked after %s, want about %s", elapsed, gatewayRestartBudget)
	}
	if !strings.Contains(result.stdout, `"permissionDecision":"deny"`) || !strings.Contains(result.stdout, "restarting or not running") {
		t.Fatalf("stdout=%q stderr=%q, want a deny naming the restart", result.stdout, result.stderr)
	}
}
