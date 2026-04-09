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

package audit

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testSplunkForwarder(t *testing.T, handler http.HandlerFunc) *SplunkForwarder {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)

	cfg := SplunkConfig{
		HECEndpoint: srv.URL,
		HECToken:    "test-token",
		Index:       "test",
		Source:      "test",
		SourceType:  "_json",
		VerifyTLS:   false,
		BatchSize:   5,
	}
	f := &SplunkForwarder{
		cfg:    cfg,
		client: srv.Client(),
		done:   make(chan struct{}),
	}
	return f
}

func makeEvent(action string) Event {
	return Event{
		ID:        "evt-" + action,
		Timestamp: time.Now().UTC(),
		Action:    action,
		Target:    "test-target",
		Actor:     "test",
		Details:   "test details",
		Severity:  "info",
	}
}

func TestSplunkForwardEventConcurrency(t *testing.T) {
	var hits atomic.Int64
	f := testSplunkForwarder(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	})

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_ = f.ForwardEvent(makeEvent("concurrent"))
		}(i)
	}
	wg.Wait()

	_ = f.Flush()

	if hits.Load() == 0 {
		t.Error("expected at least one HEC request")
	}
}

func TestSplunkFlushConcurrency(t *testing.T) {
	var hits atomic.Int64
	f := testSplunkForwarder(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	})

	for i := 0; i < 3; i++ {
		_ = f.ForwardEvent(makeEvent("pre-flush"))
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = f.Flush()
		}()
	}
	wg.Wait()
}

func TestSplunkBatchFlushesAtThreshold(t *testing.T) {
	var hits atomic.Int64
	f := testSplunkForwarder(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	})

	for i := 0; i < f.cfg.BatchSize; i++ {
		_ = f.ForwardEvent(makeEvent("batch"))
	}

	if hits.Load() < 1 {
		t.Errorf("expected flush at batch size %d, got %d HEC calls", f.cfg.BatchSize, hits.Load())
	}
}

func TestSplunkFlushRequeuesOnFailure(t *testing.T) {
	callCount := 0
	f := testSplunkForwarder(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	for i := 0; i < 3; i++ {
		_ = f.ForwardEvent(makeEvent("requeue"))
	}

	err := f.Flush()
	if err == nil {
		t.Fatal("expected error on first flush (503)")
	}

	f.mu.Lock()
	batchLen := len(f.batch)
	f.mu.Unlock()
	if batchLen != 3 {
		t.Errorf("expected 3 events requeued after failure, got %d", batchLen)
	}

	err = f.Flush()
	if err != nil {
		t.Fatalf("second flush should succeed: %v", err)
	}

	f.mu.Lock()
	batchLen = len(f.batch)
	f.mu.Unlock()
	if batchLen != 0 {
		t.Errorf("batch should be empty after successful flush, got %d", batchLen)
	}
}

func TestSplunkFlushRequeuePreservesNewEvents(t *testing.T) {
	callCount := 0
	f := testSplunkForwarder(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_ = f.ForwardEvent(makeEvent("old-1"))
	_ = f.ForwardEvent(makeEvent("old-2"))

	// First flush fails
	_ = f.Flush()

	// New event added after failed flush
	_ = f.ForwardEvent(makeEvent("new-1"))

	f.mu.Lock()
	batchLen := len(f.batch)
	f.mu.Unlock()
	if batchLen != 3 {
		t.Errorf("expected 3 events (2 requeued + 1 new), got %d", batchLen)
	}

	// Second flush should succeed with all events
	err := f.Flush()
	if err != nil {
		t.Fatalf("second flush should succeed: %v", err)
	}
}

func TestSplunkFlushEmptyBatchIsNoOp(t *testing.T) {
	var hits atomic.Int64
	f := testSplunkForwarder(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	})

	_ = f.Flush()
	if hits.Load() != 0 {
		t.Error("flush on empty batch should not call HEC")
	}
}

func TestSplunkForwarder_PeriodicFlush(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	cfg := SplunkConfig{
		HECEndpoint:   srv.URL,
		HECToken:      "test-token",
		Index:         "test",
		Source:        "test",
		SourceType:    "_json",
		VerifyTLS:     false,
		BatchSize:     100,
		FlushInterval: 1,
	}

	f := &SplunkForwarder{
		cfg:    cfg,
		client: srv.Client(),
		done:   make(chan struct{}),
	}
	f.ticker = time.NewTicker(100 * time.Millisecond)
	go f.flushLoop()

	_ = f.ForwardEvent(makeEvent("tick-1"))

	time.Sleep(300 * time.Millisecond)

	if hits.Load() < 1 {
		t.Error("periodic flush should have fired within 300ms")
	}

	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestSplunkForwarder_CloseStopsTicker(t *testing.T) {
	f := testSplunkForwarder(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	f.ticker = time.NewTicker(50 * time.Millisecond)
	go f.flushLoop()

	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	time.Sleep(100 * time.Millisecond)
}

func TestSplunkForwardEventIncludesRunID(t *testing.T) {
	var payload strings.Builder
	f := testSplunkForwarder(t, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("ReadAll: %v", err)
		}
		payload.Write(body)
		w.WriteHeader(http.StatusOK)
	})

	event := makeEvent("run-id")
	event.RunID = "splunk-run-123"

	if err := f.ForwardEvent(event); err != nil {
		t.Fatalf("ForwardEvent: %v", err)
	}
	if err := f.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	if got := payload.String(); !strings.Contains(got, `"run_id":"splunk-run-123"`) {
		t.Fatalf("expected payload to contain run_id, got %s", got)
	}
}
