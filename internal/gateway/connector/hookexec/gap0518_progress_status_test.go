// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRV518ProgressStatusDoesNotFailOpen(t *testing.T) {
	shortAnswerBudget(t, 200*time.Millisecond)
	shortProgressCeiling(t, 700*time.Millisecond)
	var seen atomic.Bool
	addr := gatewayAt(t, func(w http.ResponseWriter, r *http.Request) {
		seen.Store(true)
		w.WriteHeader(HookProgressStatus)
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	})
	client, err := NewPerUserGatewayHTTPClient(2*time.Second, addr)
	if err != nil {
		t.Fatal(err)
	}
	result, elapsed := runAgainstGateway(t, "claudecode", addr, func(opts *Options) {
		opts.HTTPClient = client
		opts.Home = t.TempDir()
		opts.FailMode = "open"
		opts.OutageFailModeNow = func() string { return "open" }
	})
	if !seen.Load() {
		t.Fatal("verified transport did not reach the gateway")
	}
	if elapsed < 500*time.Millisecond || elapsed > 2*time.Second {
		t.Fatalf("elapsed %s, want the progress ceiling", elapsed)
	}
	if !blocked(result) {
		t.Fatalf("HTTP 102 progress turned into an allow: code=%d stdout=%q stderr=%q", result.code, result.stdout, result.stderr)
	}
	if strings.Contains(result.stdout+result.stderr, "calls run unchecked") {
		t.Fatalf("HTTP 102 progress showed outage-open warning: code=%d stdout=%q stderr=%q", result.code, result.stdout, result.stderr)
	}
}

func TestGAP0518FinalStatusDoesNotFailOpen(t *testing.T) {
	shortAnswerBudget(t, 200*time.Millisecond)
	for _, row := range []struct {
		name   string
		status int
	}{
		{"busy-response", http.StatusTooManyRequests},
		{"unfinished-body", http.StatusOK},
	} {
		t.Run(row.name, func(t *testing.T) {
			addr := gatewayAt(t, func(w http.ResponseWriter, r *http.Request) {
				if row.status == http.StatusTooManyRequests {
					w.Header().Set("Retry-After", "1")
					w.WriteHeader(row.status)
					return
				}
				w.WriteHeader(row.status)
				w.(http.Flusher).Flush()
				select {
				case <-r.Context().Done():
				case <-time.After(2 * time.Second):
				}
			})
			client, err := NewPerUserGatewayHTTPClient(2*time.Second, addr)
			if err != nil {
				t.Fatal(err)
			}
			result, _ := runAgainstGateway(t, "claudecode", addr, func(opts *Options) {
				opts.HTTPClient = client
				opts.Home = t.TempDir()
				opts.FailMode = "open"
				opts.OutageFailModeNow = func() string { return "open" }
			})
			if !blocked(result) || strings.Contains(result.stdout+result.stderr, "calls run unchecked") {
				t.Fatalf("HTTP %d gave no closed answer: code=%d stdout=%q stderr=%q", row.status, result.code, result.stdout, result.stderr)
			}
		})
	}
}
