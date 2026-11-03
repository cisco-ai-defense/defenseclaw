// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"context"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestGAP0518RefusedThenProgressNeedsFinalDecision(t *testing.T) {
	fastRestartRetries(t)
	shortAnswerBudget(t, 200*time.Millisecond)
	shortProgressCeiling(t, 700*time.Millisecond)
	for _, row := range []struct {
		name, command string
		progress      bool
		final         bool
		blocked       bool
	}{
		{"pending decision", "cp a.txt .ssh/authorized_keys", true, false, true},
		{"pending append", "echo marker >> .ssh/authorized_keys", true, false, true},
		{"pending without interim status", "cp a.txt .ssh/authorized_keys", false, false, true},
		{"completed benign call", "echo marker > project/notes.txt", true, true, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			var sawProgress bool
			rt := &stubRT{onRequest: func(rt *stubRT, req *http.Request) (*http.Response, error) {
				if rt.requests == 1 {
					return nil, syscall.ECONNREFUSED
				}
				if trace := httptrace.ContextClientTrace(req.Context()); trace != nil {
					if trace.GotConn != nil {
						trace.GotConn(httptrace.GotConnInfo{})
					}
					if row.progress && trace.Got1xxResponse != nil {
						_ = trace.Got1xxResponse(HookProgressStatus, textproto.MIMEHeader{})
						sawProgress = true
					}
				}
				if row.final {
					return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"action":"allow"}`)), Header: make(http.Header)}, nil
				}
				<-req.Context().Done()
				return nil, req.Context().Err()
			}}
			result := runWithContext(t, ctx, "claudecode", rt, func(opts *Options) {
				opts.Stdin = strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":` + mustJSONString(row.command) + `}}`)
				opts.FailMode = "open"
				opts.OutageFailModeNow = func() string { return "open" }
				opts.StartedAt = time.Now()
			})
			if sawProgress != row.progress || rt.requests != 2 || claudeBlocked(result) != row.blocked {
				t.Fatalf("progress=%v requests=%d blocked=%v code=%d stdout=%q stderr=%q", sawProgress, rt.requests, claudeBlocked(result), result.code, result.stdout, result.stderr)
			}
		})
	}
}

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
