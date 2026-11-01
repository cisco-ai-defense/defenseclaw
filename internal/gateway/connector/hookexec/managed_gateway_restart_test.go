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
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func fastRestartRetries(t *testing.T) {
	t.Helper()
	previous := gatewayRestartRetryDelay
	gatewayRestartRetryDelay = 5 * time.Millisecond
	t.Cleanup(func() { gatewayRestartRetryDelay = previous })
}

// managedCodex makes opts a managed hook in the fail mode its
// administrator-owned runtime records by default, closed.
func managedCodex(opts *Options) {
	opts.ManagedEnterprise = true
	opts.FailMode = "closed"
	token := "authenticated-generation-token"
	opts.AuthenticatedManagedToken = &token
}

// failingThen answers the first n requests with err, then with the gateway's
// verdict body.
func failingThen(n int, err error, body string) *stubRT {
	return &stubRT{onRequest: func(rt *stubRT, _ *http.Request) (*http.Response, error) {
		if rt.requests <= n {
			return nil, err
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	}}
}

// #1278: a managed hook whose gateway is restarting is answered by the
// gateway that starts, from the policy it loads, instead of failing closed
// on the first refused or dropped connection.
func TestManagedHookIsAnsweredByTheGatewayThatRestarts(t *testing.T) {
	fastRestartRetries(t)
	for _, test := range []struct {
		name string
		err  error
	}{
		{"connection refused", syscall.ECONNREFUSED},
		{"service not running", fmt.Errorf("%w: %w", errManagedGatewayPeerUnverified, errManagedGatewayNotRunning)},
		{"connection dropped unanswered", io.EOF},
		{"connection reset", syscall.ECONNRESET},
	} {
		t.Run(test.name, func(t *testing.T) {
			allowed := run(t, "codex", failingThen(3, test.err, `{"action":"allow"}`), managedCodex)
			if allowed.code != 0 || allowed.rt.requests != 4 || strings.Contains(allowed.stdout, "deny") {
				t.Fatalf("allow after restart: code=%d requests=%d stdout=%q stderr=%q",
					allowed.code, allowed.rt.requests, allowed.stdout, allowed.stderr)
			}
			denied := run(t, "codex", failingThen(2, test.err, `{"action":"block","reason":"marker rule"}`), managedCodex)
			if denied.rt.requests != 3 || !strings.Contains(denied.stdout+denied.stderr, "marker rule") {
				t.Fatalf("policy deny after restart: code=%d requests=%d stdout=%q stderr=%q",
					denied.code, denied.rt.requests, denied.stdout, denied.stderr)
			}
		})
	}
}

// A restart that outlasts the budget fails closed within it, never open.
func TestManagedHookFailsClosedWhenTheRestartOutlastsTheBudget(t *testing.T) {
	fastRestartRetries(t)
	started := time.Now()
	result := run(t, "codex", &stubRT{err: syscall.ECONNREFUSED}, func(opts *Options) {
		managedCodex(opts)
		opts.StartedAt = time.Now().Add(-gatewayRestartBudget + 150*time.Millisecond)
	})
	elapsed := time.Since(started)
	if elapsed > time.Second {
		t.Fatalf("the hook waited %s past its restart budget", elapsed)
	}
	if result.rt.requests < 2 {
		t.Fatalf("requests = %d, want the call sent again within the budget", result.rt.requests)
	}
	if !strings.Contains(result.stdout, "deny") && result.code == 0 {
		t.Fatalf("an unanswered managed call was not blocked: code=%d stdout=%q", result.code, result.stdout)
	}
}

// Only restart-shaped failures are tried again, and never by a Secure
// Client hook. (Per-user hooks: per_user_gateway_restart_test.go.)
func TestOnlyRestartFailuresAreSentAgain(t *testing.T) {
	fastRestartRetries(t)
	impostor := fmt.Errorf("%w: hook socket listener uid 1000 is neither root nor the gateway service uid", errManagedGatewayPeerUnverified)
	for _, test := range []struct {
		name   string
		rt     *stubRT
		mutate func(*Options)
	}{
		{"a listener that is not the gateway", &stubRT{err: impostor}, managedCodex},
		{"a per-user timeout", &stubRT{err: context.DeadlineExceeded}, func(opts *Options) { opts.FailMode = "closed" }},
		{"Secure Client", &stubRT{err: syscall.ECONNREFUSED}, func(opts *Options) { managedCodex(opts); opts.SecureClient = true }},
		{"a timeout", &stubRT{err: context.DeadlineExceeded}, managedCodex},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := run(t, "codex", test.rt, test.mutate)
			if result.rt.requests != 1 {
				t.Fatalf("requests = %d, want 1", result.rt.requests)
			}
		})
	}
}

// A standalone call that waits in the socket systemd holds while the
// gateway restarts fails closed at the end of the restart budget, with the
// restart named, instead of waiting out the hook's whole budget (#1302: one
// call waited 16 s). It is a block in every fail mode.
func TestQueuedStandaloneCallFailsClosedWhenTheGatewayStaysDown(t *testing.T) {
	previousProbe, previousInterval := standaloneGatewayServiceProbe, gatewayStartWatchInterval
	standaloneGatewayServiceProbe = func(context.Context) (gatewayServiceState, error) {
		return gatewayServiceState{Active: "deactivating", Sub: "stop-sigterm"}, nil
	}
	gatewayStartWatchInterval = 5 * time.Millisecond
	t.Cleanup(func() { standaloneGatewayServiceProbe, gatewayStartWatchInterval = previousProbe, previousInterval })
	queued := &stubRT{onRequest: func(_ *stubRT, req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	}}
	started := time.Now()
	result := run(t, "claudecode", queued, func(opts *Options) {
		opts.ManagedEnterprise = true
		opts.ManagedStandalone = true
		opts.ManagedUnixSocket = "/run/defenseclaw-hook/hook.sock"
		opts.ManagedServiceUID = 990
		opts.FailMode = "closed"
		opts.StartedAt = time.Now().Add(-gatewayRestartBudget + 200*time.Millisecond)
	})
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("the queued call waited %s", elapsed)
	}
	if !strings.Contains(result.stdout, `"permissionDecision":"deny"`) ||
		!strings.Contains(result.stdout, "restarting") || !strings.Contains(result.stdout, managedGatewayRestartingReason) {
		t.Fatalf("stdout = %q, stderr = %q, want a deny that names the restart", result.stdout, result.stderr)
	}
}

func TestWatchGatewayStarts(t *testing.T) {
	previous := gatewayRunningWatchInterval
	gatewayRunningWatchInterval = time.Millisecond
	t.Cleanup(func() { gatewayRunningWatchInterval = previous })
	for _, test := range []struct {
		name     string
		states   []gatewayServiceState
		deadline time.Duration // from now; 0 = none
		want     error
	}{
		{"restart loop", []gatewayServiceState{{"activating", "auto-restart", 4}, {"activating", "start", 5}, {"activating", "auto-restart", 5}}, 0, errGatewayStartFailing},
		{"one crash then running", []gatewayServiceState{{"activating", "auto-restart", 4}, {"activating", "start", 5}, {"active", "running", 5}}, 0, nil},
		{"start limit reached", []gatewayServiceState{{"failed", "failed", 9}}, 0, errGatewayStartFailing},
		{"slow inspection", []gatewayServiceState{{"active", "running", 0}}, -time.Second, nil},
		{"restart within the budget", []gatewayServiceState{{"deactivating", "stop-sigterm", 0}, {"activating", "start", 0}, {"active", "running", 0}}, time.Hour, nil},
		{"restart past the budget", []gatewayServiceState{{"deactivating", "stop-sigterm", 0}}, 20 * time.Millisecond, errGatewayRestarting},
		{"stopped under an accepted call", []gatewayServiceState{{"active", "running", 0}, {"deactivating", "stop-sigterm", 0}}, -time.Second, errGatewayRestarting},
		{"no budget keeps the wait", []gatewayServiceState{{"deactivating", "stop-sigterm", 0}}, 0, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int64
			done := make(chan struct{})
			probe := func(context.Context) (gatewayServiceState, error) {
				n := int(calls.Add(1))
				if n == 50 {
					close(done) // the response arrived
				}
				return test.states[min(n-1, len(test.states)-1)], nil
			}
			var deadline time.Time
			if test.deadline != 0 {
				deadline = time.Now().Add(test.deadline)
			}
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			finished := make(chan struct{})
			go func() {
				watchGatewayStarts(ctx, done, cancel, probe, time.Millisecond, deadline)
				close(finished)
			}()
			select {
			case <-finished:
			case <-time.After(10 * time.Second):
				t.Fatal("the watch did not end")
			}
			if got := context.Cause(ctx); !errors.Is(got, test.want) || (test.want == nil && got != nil) {
				t.Fatalf("cause = %v after %d probes, want %v", got, calls.Load(), test.want)
			}
		})
	}
}

// The foreign-hook session exchange, the first gateway call of a standalone
// hook, rides out a restart the same way, with the same full body each try.
func TestForeignHookSessionExchangeIsSentAgainWhileTheGatewayRestarts(t *testing.T) {
	fastRestartRetries(t)
	var calls int
	var first string
	opts := Options{ManagedEnterprise: true, ManagedStandalone: true, APIAddr: "127.0.0.1:18970"}
	opts.HTTPClient = &http.Client{Transport: foreignSessionRoundTrip(func(req *http.Request) (*http.Response, error) {
		calls++
		body, _ := io.ReadAll(req.Body)
		if first == "" {
			first = string(body)
		}
		if string(body) != first || withoutRetryUntil(t, body) != `{"key":{"connector":"claudecode"}}` {
			t.Fatalf("try %d sent %q", calls, body)
		}
		if calls < 3 {
			return nil, syscall.ECONNREFUSED
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"deny":false}`))}, nil
	})}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	response, err := ExchangeForeignHookSession(ctx, opts, "claudecode", []byte(`{"key":{"connector":"claudecode"}}`))
	if err != nil || string(response) != `{"deny":false}` || calls != 3 {
		t.Fatalf("exchange = %q, error %v, calls %d", response, err, calls)
	}
}
