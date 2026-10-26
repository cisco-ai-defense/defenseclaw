// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// GAP-1711: during a five-agent cold start the gateway answered one benign
// exchange with the session-record denial (no hook named, no finding). The
// exchange of a scan that allowed the call is sent again and the call runs;
// a scan that found an unapproved hook, another denial, and a record that
// stays unavailable keep their denial.
func TestForeignHookSessionExchangeRetriesARecordStoreDenialOfACleanScan(t *testing.T) {
	busy, _ := json.Marshal(map[string]any{"deny": true, "reason": ForeignHookSessionRecordUnavailableReason})
	allow := []byte(`{"findings":null,"deny":false}`)
	foreign := []byte(`{"deny":true,"reason":"enterprise_foreign_hook_blocked: your organization blocks copilot hooks it has not approved"}`)
	clean := []byte(`{"key":{"connector":"opencode"},"decision":{"findings":null,"deny":false}}`)
	found := []byte(`{"key":{"connector":"opencode"},"decision":{"findings":[{"path":"x"}],"deny":true,"reason":"enterprise_foreign_hook_blocked: x"}}`)
	cases := []struct {
		name    string
		payload []byte
		answers [][]byte
		want    []byte
		calls   int32
	}{
		{"clean scan, store busy once", clean, [][]byte{busy, allow}, allow, 2},
		{"clean scan, store busy twice", clean, [][]byte{busy, busy, allow}, allow, 3},
		{"clean scan, store stays busy", clean, [][]byte{busy, busy, busy, allow}, busy, 3},
		{"clean scan, real denial", clean, [][]byte{foreign, allow}, foreign, 1},
		{"scan found a hook", found, [][]byte{busy, allow}, busy, 1},
		{"clean scan, allowed", clean, [][]byte{allow}, allow, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			opts := Options{ManagedEnterprise: true, ManagedStandalone: true, APIAddr: "127.0.0.1:18970", StartedAt: time.Now()}
			opts.HTTPClient = &http.Client{Transport: foreignSessionRoundTrip(func(req *http.Request) (*http.Response, error) {
				n := calls.Add(1)
				body, _ := io.ReadAll(req.Body)
				if string(body) != string(tc.payload) {
					t.Fatalf("exchange %d sent %q, want the same scan", n, body)
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(tc.answers[n-1])))}, nil
			})}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			got, err := ExchangeForeignHookSession(ctx, opts, "opencode", tc.payload)
			if err != nil || string(got) != string(tc.want) {
				t.Fatalf("exchange = %q, %v; want %q", got, err, tc.want)
			}
			if calls.Load() != tc.calls {
				t.Fatalf("exchanges sent = %d, want %d", calls.Load(), tc.calls)
			}
		})
	}
}

// A retry never eats the time the hook request after it needs.
func TestForeignHookSessionExchangeRetriesOnlyWithinTheBudget(t *testing.T) {
	busy, _ := json.Marshal(map[string]any{"deny": true, "reason": ForeignHookSessionRecordUnavailableReason})
	var calls atomic.Int32
	opts := Options{ManagedEnterprise: true, ManagedStandalone: true, APIAddr: "127.0.0.1:18970", StartedAt: time.Now()}
	opts.HTTPClient = &http.Client{Transport: foreignSessionRoundTrip(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(busy)))}, nil
	})}
	ctx, cancel := context.WithTimeout(context.Background(), foreignHookSessionRecordRetryReserve/2)
	defer cancel()
	got, err := ExchangeForeignHookSession(ctx, opts, "opencode", []byte(`{"decision":{"deny":false}}`))
	if err != nil || string(got) != string(busy) || calls.Load() != 1 {
		t.Fatalf("exchange = %q, %v after %d tries; want the denial after one", got, err, calls.Load())
	}
}
