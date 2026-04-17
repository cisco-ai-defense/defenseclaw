// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/audit/sinks"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

// hecCapture records every Splunk HEC request received by the mock
// collector. It is safe for concurrent use because the test server
// runs each request in its own goroutine.
type hecCapture struct {
	mu      sync.Mutex
	records [][]byte
}

func (c *hecCapture) append(b []byte) {
	c.mu.Lock()
	c.records = append(c.records, b)
	c.mu.Unlock()
}

func (c *hecCapture) all() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([][]byte, len(c.records))
	copy(out, c.records)
	return out
}

// TestCorrelation_RequestIDSharedAcrossJSONLSQLiteAndSplunk is the
// Phase 5 capstone integration test. It asserts the same request_id
// flows through all three observability tiers for a single
// judge invocation:
//
//  1. SQLite (audit_events.request_id column) — written by
//     logger.LogEvent("llm-judge-response").
//  2. gateway.jsonl (top-level request_id field) — written by the
//     native emitJudge path in production. The audit bridge
//     intentionally skips "llm-judge-response" so JSONL is not
//     double-emitted; this test reproduces that production contract
//     by calling writer.Emit with an EventJudge payload alongside
//     LogEvent, matching what sidecar.go does at runtime.
//  3. Splunk HEC (inner event.request_id with the judge-specific
//     defenseclaw:judge sourcetype override) — written by the
//     logger sink fan-out.
//
// Without this invariant, SOC teams pivoting between local forensics
// and the enterprise SIEM silently lose the correlation key — the
// single most important signal for incident response.
func TestCorrelation_RequestIDSharedAcrossJSONLSQLiteAndSplunk(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "audit.db")
	jsonlPath := filepath.Join(tmp, "gateway.jsonl")

	// 1. SQLite store with full migrations.
	store, err := audit.NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.Init(); err != nil {
		t.Fatalf("store.Init: %v", err)
	}
	defer store.Close()

	// 2. gatewaylog writer (gateway.jsonl).
	writer, err := gatewaylog.New(gatewaylog.Config{JSONLPath: jsonlPath})
	if err != nil {
		t.Fatalf("gatewaylog.New: %v", err)
	}
	defer writer.Close()

	// 3. Splunk HEC mock. Captures every envelope for later assertions.
	capture := &hecCapture{}
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			capture.append(body)
			w.WriteHeader(http.StatusOK)
		}))
	defer srv.Close()

	// BatchSize=1 + immediate flush on `llm-judge-response` means we
	// get synchronous delivery of the single test event. FlushIntervalS
	// is kept long so the ticker cannot race with assertions.
	splunk, err := sinks.NewSplunkHECSink(sinks.SplunkHECConfig{
		Name:           "splunk-mock",
		Endpoint:       srv.URL,
		Token:          "t",
		BatchSize:      1,
		FlushIntervalS: 3600,
	})
	if err != nil {
		t.Fatalf("NewSplunkHECSink: %v", err)
	}
	defer splunk.Close()

	mgr := sinks.NewManager()
	mgr.Register(splunk)
	// llm-judge-response is included in default immediate flush
	// actions; leaving it at the default exercises the production
	// code path. Verdicts also flush immediately for the same reason.

	// 4. Wire the logger.
	logger := audit.NewLogger(store)
	logger.SetSinks(mgr)
	logger.SetStructuredEmitter(newAuditBridge(writer))
	defer logger.Close()

	const wantRequestID = "req-correlation-test-0001"
	const wantTraceID = "trace-correlation-test"
	eventTime := time.Date(2026, 4, 16, 12, 0, 0, 0, time.UTC)

	// Mirror the production fan-out for an llm-judge-response:
	//
	//   * logger.LogEvent     → SQLite audit row + Splunk HEC envelope
	//   * writer.Emit(Judge)  → gateway.jsonl EventJudge row
	//
	// The audit bridge skips "llm-judge-response" (see
	// skipBridgeAction) so JSONL is written only once, via the native
	// emitter. This test exercises both legs so an end-to-end
	// regression on either side still trips the assertions below.
	// writer.Emit is fire-and-forget (drops the event on queue
	// overflow rather than blocking callers in the hot-path). The
	// downstream capture wait-loop below is what gates correctness.
	writer.Emit(gatewaylog.Event{
		Timestamp: eventTime,
		EventType: gatewaylog.EventJudge,
		Severity:  gatewaylog.SeverityHigh,
		RunID:     "run-corr-1",
		RequestID: wantRequestID,
		Provider:  "anthropic",
		Model:     "anthropic/claude-3-sonnet",
		Direction: gatewaylog.DirectionPrompt,
		Judge: &gatewaylog.JudgePayload{
			Kind:       "pii",
			Model:      "anthropic/claude-3-sonnet",
			InputBytes: 42,
			LatencyMs:  42,
			Action:     "alert",
			Severity:   gatewaylog.SeverityHigh,
		},
	})

	err = logger.LogEvent(audit.Event{
		Timestamp: eventTime,
		Action:    "llm-judge-response",
		Target:    "anthropic/claude-3-sonnet",
		Actor:     "defenseclaw-gateway",
		Details:   "kind=pii direction=input action=alert latency_ms=42",
		Severity:  "HIGH",
		TraceID:   wantTraceID,
		RequestID: wantRequestID,
	})
	if err != nil {
		t.Fatalf("LogEvent: %v", err)
	}

	// Immediate-flush actions schedule an async FlushAll; wait on it.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(capture.all()) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// ---- Assert SQLite row has request_id + trace_id. ----
	t.Run("sqlite_has_request_id", func(t *testing.T) {
		events, err := store.ListEvents(10)
		if err != nil {
			t.Fatalf("ListEvents: %v", err)
		}
		var match *audit.Event
		for i := range events {
			if events[i].Action == "llm-judge-response" {
				match = &events[i]
				break
			}
		}
		if match == nil {
			t.Fatal("no llm-judge-response row in audit_events")
		}
		if match.RequestID != wantRequestID {
			t.Fatalf("sqlite request_id=%q want %q", match.RequestID, wantRequestID)
		}
		if match.TraceID != wantTraceID {
			t.Fatalf("sqlite trace_id=%q want %q", match.TraceID, wantTraceID)
		}
		if match.Severity != "HIGH" {
			t.Fatalf("sqlite severity=%q want HIGH", match.Severity)
		}
	})

	// ---- Assert gateway.jsonl has a judge row with matching request_id. ----
	//
	// The expected shape is event_type=judge (written by writer.Emit
	// above), NOT a lifecycle twin from the audit bridge. A lifecycle
	// row with action=llm-judge-response would mean skipBridgeAction
	// regressed and we are double-emitting judges.
	t.Run("jsonl_has_request_id", func(t *testing.T) {
		f, err := os.Open(jsonlPath)
		if err != nil {
			t.Fatalf("open jsonl: %v", err)
		}
		defer f.Close()

		seenJudge := false
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for scanner.Scan() {
			var ev struct {
				RequestID string `json:"request_id"`
				EventType string `json:"event_type"`
				Lifecycle struct {
					Details map[string]string `json:"details"`
				} `json:"lifecycle"`
			}
			if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
				t.Fatalf("bad jsonl line: %v (%s)", err, scanner.Text())
			}
			if ev.EventType == "judge" {
				if ev.RequestID != wantRequestID {
					t.Fatalf("jsonl judge request_id=%q want %q",
						ev.RequestID, wantRequestID)
				}
				seenJudge = true
			}
			if ev.EventType == "lifecycle" &&
				ev.Lifecycle.Details["action"] == "llm-judge-response" {
				t.Fatalf("audit bridge leaked an llm-judge-response " +
					"lifecycle row — skipBridgeAction regressed")
			}
		}
		if err := scanner.Err(); err != nil {
			t.Fatalf("scanner: %v", err)
		}
		if !seenJudge {
			t.Fatal("gateway.jsonl never received the native judge event")
		}
	})

	// ---- Assert Splunk HEC envelope carries request_id + override. ----
	t.Run("splunk_has_request_id_and_sourcetype", func(t *testing.T) {
		records := capture.all()
		if len(records) == 0 {
			t.Fatal("splunk HEC never received any events")
		}
		seen := false
		for _, raw := range records {
			for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
				if line == "" {
					continue
				}
				var env struct {
					SourceType string `json:"sourcetype"`
					Event      struct {
						Action    string `json:"action"`
						RequestID string `json:"request_id"`
						TraceID   string `json:"trace_id"`
					} `json:"event"`
				}
				if err := json.Unmarshal([]byte(line), &env); err != nil {
					t.Fatalf("bad HEC envelope: %v (%s)", err, line)
				}
				if env.Event.Action != "llm-judge-response" {
					continue
				}
				if env.SourceType != "defenseclaw:judge" {
					t.Fatalf("splunk sourcetype=%q want defenseclaw:judge",
						env.SourceType)
				}
				if env.Event.RequestID != wantRequestID {
					t.Fatalf("splunk request_id=%q want %q",
						env.Event.RequestID, wantRequestID)
				}
				if env.Event.TraceID != wantTraceID {
					t.Fatalf("splunk trace_id=%q want %q",
						env.Event.TraceID, wantTraceID)
				}
				seen = true
			}
		}
		if !seen {
			t.Fatal("no llm-judge-response envelope found in splunk HEC capture")
		}
	})
}

// TestCorrelation_MultipleRequestsKeepDistinctIDs guards against the
// classic fan-out bug where a shared writer captures a request_id in
// a closure and reuses it for subsequent events. We drive multiple
// judge invocations with different request IDs back-to-back and
// verify both sinks segregate them.
//
// We emit via writer.Emit(EventJudge) (the production JSONL path)
// plus logger.LogEvent (the SQLite path); the audit bridge no longer
// forwards llm-judge-response so the JSONL row must come from the
// native emitter.
func TestCorrelation_MultipleRequestsKeepDistinctIDs(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "audit.db")
	jsonlPath := filepath.Join(tmp, "gateway.jsonl")

	store, err := audit.NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.Init(); err != nil {
		t.Fatalf("store.Init: %v", err)
	}
	defer store.Close()

	writer, err := gatewaylog.New(gatewaylog.Config{JSONLPath: jsonlPath})
	if err != nil {
		t.Fatalf("gatewaylog.New: %v", err)
	}
	defer writer.Close()

	logger := audit.NewLogger(store)
	logger.SetStructuredEmitter(newAuditBridge(writer))
	defer logger.Close()

	reqIDs := []string{"req-alpha-001", "req-bravo-002", "req-charlie-003"}
	for i, rid := range reqIDs {
		ts := time.Now().UTC().Add(time.Duration(i) * time.Millisecond)
		writer.Emit(gatewaylog.Event{
			Timestamp: ts,
			EventType: gatewaylog.EventJudge,
			Severity:  gatewaylog.SeverityInfo,
			RequestID: rid,
			Judge: &gatewaylog.JudgePayload{
				Kind:       "pii",
				Model:      "model-x",
				InputBytes: 1,
				LatencyMs:  1,
			},
		})
		if err := logger.LogEvent(audit.Event{
			Timestamp: ts,
			Action:    "llm-judge-response",
			Target:    "model-x",
			Details:   "row " + rid,
			Severity:  "INFO",
			RequestID: rid,
		}); err != nil {
			t.Fatalf("LogEvent %s: %v", rid, err)
		}
	}

	// SQLite side — three distinct request_ids must appear.
	// ListEvents returns DESC; reverse-iterate so order matches
	// the insertion order of reqIDs.
	events, err := store.ListEvents(10)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	gotDB := []string{}
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Action == "llm-judge-response" {
			gotDB = append(gotDB, events[i].RequestID)
		}
	}
	if len(gotDB) != len(reqIDs) {
		t.Fatalf("sqlite rows=%d want %d", len(gotDB), len(reqIDs))
	}
	for i, want := range reqIDs {
		if gotDB[i] != want {
			t.Fatalf("sqlite row %d request_id=%q want %q", i, gotDB[i], want)
		}
	}

	// JSONL side — three distinct top-level request_ids on EventJudge
	// rows. A lifecycle row with action=llm-judge-response would
	// indicate the audit bridge regressed and started double-emitting.
	f, err := os.Open(jsonlPath)
	if err != nil {
		t.Fatalf("open jsonl: %v", err)
	}
	defer f.Close()
	gotJSONL := []string{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		var ev struct {
			RequestID string `json:"request_id"`
			EventType string `json:"event_type"`
			Lifecycle struct {
				Details map[string]string `json:"details"`
			} `json:"lifecycle"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			t.Fatalf("jsonl parse: %v", err)
		}
		if ev.EventType == "judge" {
			gotJSONL = append(gotJSONL, ev.RequestID)
			continue
		}
		if ev.EventType == "lifecycle" &&
			ev.Lifecycle.Details["action"] == "llm-judge-response" {
			t.Fatalf("audit bridge leaked llm-judge-response into JSONL")
		}
	}
	if len(gotJSONL) != len(reqIDs) {
		t.Fatalf("jsonl judge rows=%d want %d", len(gotJSONL), len(reqIDs))
	}
	for i, want := range reqIDs {
		if gotJSONL[i] != want {
			t.Fatalf("jsonl row %d request_id=%q want %q", i, gotJSONL[i], want)
		}
	}
}
