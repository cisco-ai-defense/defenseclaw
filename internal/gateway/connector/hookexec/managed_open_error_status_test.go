// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// r104 W6 review (fix/r104-windows): with the administrator's open fail
// mode a standalone hook let a tool call through when the gateway answered
// with an error status it could not finish reading (a 5xx or 4xx whose body
// was cut off) and when it answered 429 with a Retry-After past the answer
// budget: both reached failNoAnswer, which counts as the outage open lets
// through. The gateway answered in both cases, so the call is blocked, as
// the fail-modes table says for 5xx and 4xx. Only an eligible service outage
// opens, and closed blocks everything.
func TestStandaloneManagedOpenBlocksErrorStatusesThatAreNotAnOutage(t *testing.T) {
	standalone := func(mode string) func(*Options) {
		return func(o *Options) {
			managedCodex(o)
			o.ExplainUnenrolledAccount = true
			o.FailMode = mode
		}
	}
	cutOff := func(status int) *stubRT {
		return &stubRT{onRequest: func(_ *stubRT, _ *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: status, Header: make(http.Header),
				Body: io.NopCloser(&failingReader{data: []byte(`{"error":"intern`)})}, nil
		}}
	}
	oversized := func(status int) *stubRT {
		return &stubRT{onRequest: func(_ *stubRT, _ *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: status, Header: make(http.Header),
				Body: io.NopCloser(strings.NewReader(`{"error":"` + strings.Repeat("x", int(defaultMaxBody)+16) + `"}`))}, nil
		}}
	}
	notRunning := fmt.Errorf("%w: %w", errManagedGatewayPeerUnverified, errManagedGatewayNotRunning)
	for _, mode := range []string{"open", "closed"} {
		for _, tc := range []struct {
			name string
			rt   *stubRT
			// allowedOpen: the one row an open standalone hook lets through.
			allowedOpen bool
			mutate      func(*Options)
		}{
			{name: "5xx with a body cut off", rt: cutOff(http.StatusServiceUnavailable)},
			{name: "500 with a body cut off", rt: cutOff(http.StatusInternalServerError)},
			{name: "5xx with an oversized body", rt: oversized(http.StatusBadGateway)},
			{name: "4xx with a body cut off", rt: cutOff(http.StatusNotFound)},
			{name: "400 with an oversized body", rt: oversized(http.StatusBadRequest)},
			{name: "401 with a body cut off", rt: cutOff(http.StatusUnauthorized)},
			{name: "complete 5xx", rt: &stubRT{status: http.StatusServiceUnavailable, body: "unavailable"}},
			{name: "complete 4xx", rt: &stubRT{status: http.StatusConflict, body: `{"error":"conflict"}`}},
			{name: "oversized input", rt: ok(`{"action":"allow"}`), mutate: func(o *Options) { o.MaxBody = 8 }},
			{name: "gateway service not running", rt: &stubRT{err: notRunning}, allowedOpen: true},
			{name: "transport error that is not an outage", rt: &stubRT{err: errors.New("offline")}},
		} {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				result := run(t, "codex", tc.rt, func(o *Options) {
					standalone(mode)(o)
					if tc.mutate != nil {
						tc.mutate(o)
					}
				})
				want := mode != "open" || !tc.allowedOpen
				if blocked(result) != want {
					t.Fatalf("blocked = %v, want %v: code=%d stdout=%q stderr=%q", blocked(result), want, result.code, result.stdout, result.stderr)
				}
			})
		}
	}
}

// The 429 half of the same review: a busy gateway whose Retry-After does not
// fit the answer budget (or whose wait the budget cuts off) answered the
// call, so an open standalone hook blocks it. A per-user hook in fail mode
// open does not turn a missed tool-call deadline into an unaudited allow.
func TestStandaloneManagedOpenBlocksABusyGatewayPastTheAnswerBudget(t *testing.T) {
	for _, retryAfter := range []string{"3", "1"} {
		t.Run("retry-after "+retryAfter, func(t *testing.T) {
			shortAnswerBudget(t, 1500*time.Millisecond)
			addr := gatewayAt(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Retry-After", retryAfter)
				w.WriteHeader(http.StatusTooManyRequests)
			})
			standalone, _ := runAgainstGateway(t, "codex", addr, func(o *Options) {
				managedCodex(o)
				o.ExplainUnenrolledAccount = true
				o.FailMode = "open"
			})
			if !blocked(standalone) || !strings.Contains(standalone.stdout+standalone.stderr, managedGatewayNoAnswerReason) {
				t.Fatalf("open standalone hook and a busy gateway: code=%d stdout=%q stderr=%q", standalone.code, standalone.stdout, standalone.stderr)
			}
			perUser, _ := runAgainstGateway(t, "codex", addr, func(o *Options) { o.FailMode = "open" })
			if !blocked(perUser) {
				t.Fatalf("per-user open hook allowed an unanswered call: code=%d stdout=%q stderr=%q", perUser.code, perUser.stdout, perUser.stderr)
			}
		})
	}
}
