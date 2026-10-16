// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestRouterFeedback_Record_Success(t *testing.T) {
	var mu sync.Mutex
	var received []feedbackEntry

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/feedback" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var entry feedbackEntry
		if err := json.Unmarshal(body, &entry); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		mu.Lock()
		received = append(received, entry)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	rf := NewRouterFeedback(ctx, srv.URL)
	rf.Record("reasoning", "complex_reasoning", 1250*time.Millisecond, 450, true, "abc123")

	// Give the background goroutine time to drain
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	if len(received) != 1 {
		t.Fatalf("expected 1 feedback entry, got %d", len(received))
	}

	entry := received[0]
	if entry.Model != "reasoning" {
		t.Errorf("expected model=reasoning, got %q", entry.Model)
	}
	if entry.Decision != "complex_reasoning" {
		t.Errorf("expected decision=complex_reasoning, got %q", entry.Decision)
	}
	if entry.LatencyMs != 1250 {
		t.Errorf("expected latency_ms=1250, got %d", entry.LatencyMs)
	}
	if entry.Tokens != 450 {
		t.Errorf("expected tokens=450, got %d", entry.Tokens)
	}
	if !entry.Success {
		t.Errorf("expected success=true, got false")
	}
	if entry.SessionID != "abc123" {
		t.Errorf("expected session_id=abc123, got %q", entry.SessionID)
	}
}

func TestRouterFeedback_Record_ChannelFull(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Slow handler to block draining
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	rf := NewRouterFeedback(ctx, srv.URL)

	// Fill the channel (100 capacity)
	for i := 0; i < 100; i++ {
		rf.Record("model", "decision", time.Second, 100, true, "")
	}

	// Verify that Record doesn't block when channel is full
	done := make(chan bool, 1)
	go func() {
		rf.Record("overflow", "dropped", time.Second, 100, true, "")
		done <- true
	}()

	select {
	case <-done:
		// Good, it returned immediately
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Record blocked when channel was full")
	}
}

func TestRouterFeedback_Record_SRDown(t *testing.T) {
	// No server running at this address
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	rf := NewRouterFeedback(ctx, "http://127.0.0.1:9999")

	// Should not panic or hang
	rf.Record("model", "decision", time.Second, 100, true, "session123")

	// Give time for the send to fail
	time.Sleep(100 * time.Millisecond)

	// If we get here without panic, test passes
}

func TestRouterFeedback_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	rf := NewRouterFeedback(ctx, srv.URL)

	// Record an entry
	rf.Record("model", "decision", time.Second, 100, true, "")

	// Cancel context immediately
	cancel()

	// Give time for drain goroutine to exit
	time.Sleep(100 * time.Millisecond)

	// Try to record after cancellation - should not crash
	rf.Record("model2", "decision2", time.Second, 100, true, "")

	// If we get here without panic or deadlock, test passes
}
