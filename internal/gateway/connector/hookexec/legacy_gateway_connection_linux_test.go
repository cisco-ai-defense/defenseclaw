// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// An earlier gateway can answer this ordinary call as soon as the hook
// finishes its request body. Its health handler is independently delayed.
func TestReviewG271OlderGatewaySlowHealthStillAllowsBenignCall(t *testing.T) {
	shortAnswerBudget(t, 1500*time.Millisecond)
	received := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			time.Sleep(2 * time.Second)
			w.WriteHeader(http.StatusOK)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			received <- err.Error()
			return
		}
		received <- string(body)
		_, _ = io.WriteString(w, "{\"action\":\"allow\",\"codex_output\":{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"allow\"}}}\n")
	}))
	defer server.Close()
	result, elapsed := runAgainstGateway(t, "codex", server.Listener.Addr().String(), func(opts *Options) {
		opts.FailMode = "open"
	})
	if blocked(result) {
		t.Fatalf("ordinary allow became block after %s: code=%d stdout=%q stderr=%q", elapsed, result.code, result.stdout, result.stderr)
	}
	select {
	case got := <-received:
		if got == "" {
			t.Fatal("earlier gateway saw an empty body")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("earlier gateway did not receive the released body")
	}
}

// The extra compatibility wait also consumes an earlier gateway's answer
// window when its health response is prompt and its ordinary verdict is slow.
func TestReviewG271OlderGatewayLateBenignAnswerStillAllows(t *testing.T) {
	shortAnswerBudget(t, 3*time.Second)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if _, err := io.ReadAll(r.Body); err != nil {
			return
		}
		time.Sleep(2600 * time.Millisecond)
		_, _ = io.WriteString(w, "{\"action\":\"allow\",\"codex_output\":{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"allow\"}}}\n")
	}))
	defer server.Close()
	result, elapsed := runAgainstGateway(t, "codex", server.Listener.Addr().String(), func(opts *Options) {
		opts.FailMode = "open"
	})
	if blocked(result) {
		t.Fatalf("older gateway's ordinary allow became block after %s: code=%d stdout=%q stderr=%q", elapsed, result.code, result.stdout, result.stderr)
	}
}

// The POST can remain on the prior process while a replacement process
// binds the same configured listener and answers the separate health probe.
func TestReviewG271UpgradeHealthDoesNotVouchForOlderPOST(t *testing.T) {
	shortAnswerBudget(t, 1500*time.Millisecond)
	oldGateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			return
		}
		_, _ = io.WriteString(w, "{\"action\":\"allow\",\"codex_output\":{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"allow\"}}}\n")
	}))
	defer oldGateway.Close()
	currentGateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("X-DefenseClaw-Hook-Delivery-Capability", "1")
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer currentGateway.Close()
	var connections atomic.Int32
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			target := oldGateway.Listener.Addr().String()
			if connections.Add(1) > 1 {
				target = currentGateway.Listener.Addr().String()
			}
			return (&net.Dialer{}).DialContext(ctx, network, target)
		},
	}}
	result, elapsed := runAgainstGateway(t, "codex", oldGateway.Listener.Addr().String(), func(opts *Options) {
		opts.FailMode = "open"
		opts.HTTPClient = client
	})
	if blocked(result) {
		t.Fatalf("ordinary allow on prior accepted POST became block after %s: code=%d stdout=%q stderr=%q, connections=%d", elapsed, result.code, result.stdout, result.stderr, connections.Load())
	}
}
