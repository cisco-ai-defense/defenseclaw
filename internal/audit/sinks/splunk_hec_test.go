// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package sinks

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewSplunkHECSink_ValidatesConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  SplunkHECConfig
	}{
		{"missing endpoint", SplunkHECConfig{Token: "t"}},
		{"missing token", SplunkHECConfig{Endpoint: "https://splunk.example:8088"}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewSplunkHECSink(tt.cfg); err == nil {
				t.Fatalf("expected validation error")
			}
		})
	}
}

func TestSplunkHECSink_AppliesDefaultsAndAuthHeader(t *testing.T) {
	srv, records, mu, _ := httpEchoServer(t, http.StatusOK)
	sink, err := NewSplunkHECSink(SplunkHECConfig{
		Name:           "splunk",
		Endpoint:       srv.URL,
		Token:          "hec-token-xyz",
		BatchSize:      1,
		FlushIntervalS: 60, // keep ticker inert for test determinism
	})
	if err != nil {
		t.Fatalf("NewSplunkHECSink err=%v", err)
	}
	defer sink.Close()

	// Forward + manual Flush because batch=1 still routes through the
	// batch buffer (sink only sends on Flush or on batch-full).
	// Use a plain audit action so the per-event sourcetype override
	// does not kick in — that behaviour has its own dedicated test.
	_ = sink.Forward(context.Background(),
		Event{ID: "verdict-1", Action: "skill-scan",
			Severity: "HIGH", Timestamp: time.Unix(1700000000, 0).UTC(),
			SchemaVersion: 7, BinaryVersion: "unit-test",
			SessionID: "sess-1", TurnID: "turn-1",
			Structured: map[string]any{"stage": "guardrail", "action": "block"}})

	mu.Lock()
	defer mu.Unlock()
	if len(*records) != 1 {
		t.Fatalf("records=%d want 1 (batch=1 must flush on batch-full)", len(*records))
	}
	r := (*records)[0]
	if got := r.header.Get("Authorization"); got != "Splunk hec-token-xyz" {
		t.Fatalf("Authorization=%q", got)
	}
	if got := r.header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type=%q", got)
	}

	// HEC envelope shape assertions: outer has time/source/sourcetype,
	// inner `event` carries the structured payload.
	var envelope struct {
		Time       float64 `json:"time"`
		Source     string  `json:"source"`
		SourceType string  `json:"sourcetype"`
		Event      struct {
			ID            string         `json:"id"`
			Action        string         `json:"action"`
			Severity      string         `json:"severity"`
			SchemaVersion int            `json:"schema_version"`
			BinaryVersion string         `json:"binary_version"`
			SessionID     string         `json:"session_id"`
			TurnID        string         `json:"turn_id"`
			Structured    map[string]any `json:"structured"`
		} `json:"event"`
	}
	if err := json.Unmarshal(r.body, &envelope); err != nil {
		t.Fatalf("envelope JSON: %v (%s)", err, r.body)
	}
	if envelope.Source != "defenseclaw" {
		t.Fatalf("Source=%q (default must be defenseclaw)", envelope.Source)
	}
	if envelope.SourceType != "_json" {
		t.Fatalf("SourceType=%q (default must be _json)", envelope.SourceType)
	}
	if envelope.Event.ID != "verdict-1" || envelope.Event.Action != "skill-scan" {
		t.Fatalf("inner event wrong: %+v", envelope.Event)
	}
	if envelope.Event.SchemaVersion != 7 {
		t.Fatalf("schema_version = %d, want 7", envelope.Event.SchemaVersion)
	}
	if envelope.Event.BinaryVersion != "unit-test" {
		t.Fatalf("binary_version = %q, want unit-test", envelope.Event.BinaryVersion)
	}
	if envelope.Event.SessionID != "sess-1" || envelope.Event.TurnID != "turn-1" {
		t.Fatalf("correlation fields wrong: %+v", envelope.Event)
	}
	if envelope.Event.Structured["stage"] != "guardrail" {
		t.Fatalf("structured dropped: %+v", envelope.Event.Structured)
	}
}

// TestSplunkHECSink_EmitsTopLevelConnector pins the multi-connector
// contract: a connector-attributed audit event must surface the
// connector as a first-class top-level field on the indexed HEC event
// so Splunk searches can `... connector="codex"` without coalescing it
// out of the structured payload.
func TestSplunkHECSink_EmitsTopLevelConnector(t *testing.T) {
	srv, records, mu, _ := httpEchoServer(t, http.StatusOK)
	sink, err := NewSplunkHECSink(SplunkHECConfig{
		Endpoint:       srv.URL,
		Token:          "t",
		BatchSize:      1,
		FlushIntervalS: 60,
	})
	if err != nil {
		t.Fatalf("NewSplunkHECSink err=%v", err)
	}
	defer sink.Close()

	_ = sink.Forward(context.Background(), Event{
		ID: "hook-1", Action: "connector-hook", Severity: "INFO",
		Connector: "codex", Timestamp: time.Unix(1700000000, 0).UTC(),
	})

	mu.Lock()
	defer mu.Unlock()
	if len(*records) != 1 {
		t.Fatalf("records=%d want 1", len(*records))
	}
	var envelope struct {
		Event struct {
			Connector string `json:"connector"`
		} `json:"event"`
	}
	if err := json.Unmarshal((*records)[0].body, &envelope); err != nil {
		t.Fatalf("envelope JSON: %v (%s)", err, (*records)[0].body)
	}
	if envelope.Event.Connector != "codex" {
		t.Fatalf("top-level connector = %q, want codex", envelope.Event.Connector)
	}
}

func TestSplunkHECSink_RequeuesOnNon200(t *testing.T) {
	srv, records, mu, code := httpEchoServer(t, http.StatusForbidden)
	sink, err := NewSplunkHECSink(SplunkHECConfig{
		Endpoint:       srv.URL,
		Token:          "t",
		BatchSize:      2,
		FlushIntervalS: 60,
	})
	if err != nil {
		t.Fatalf("NewSplunkHECSink err=%v", err)
	}
	defer sink.Close()

	_ = sink.Forward(context.Background(), Event{ID: "1", Action: "a"})
	if err := sink.Forward(context.Background(), Event{ID: "2", Action: "a"}); err == nil {
		t.Fatal("expected 403 error")
	}

	atomic.StoreInt32(code, http.StatusOK)
	if err := sink.Flush(context.Background()); err != nil {
		t.Fatalf("recovery Flush err=%v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(*records) < 2 {
		t.Fatalf("records=%d; want >=2 (first failed, second succeeded)", len(*records))
	}
	last := string((*records)[len(*records)-1].body)
	if !strings.Contains(last, `"id":"1"`) || !strings.Contains(last, `"id":"2"`) {
		t.Fatalf("requeued events missing from recovered payload: %s", last)
	}
}

func TestSplunkHECSink_FilterSuppressesLowSeverity(t *testing.T) {
	srv, records, mu, _ := httpEchoServer(t, http.StatusOK)
	sink, err := NewSplunkHECSink(SplunkHECConfig{
		Endpoint:       srv.URL,
		Token:          "t",
		BatchSize:      1,
		FlushIntervalS: 60,
		Filter:         SinkFilter{MinSeverity: "HIGH"},
	})
	if err != nil {
		t.Fatalf("NewSplunkHECSink err=%v", err)
	}
	defer sink.Close()

	_ = sink.Forward(context.Background(), Event{ID: "low", Severity: "LOW"})
	_ = sink.Forward(context.Background(), Event{ID: "hi", Severity: "HIGH"})

	mu.Lock()
	defer mu.Unlock()
	if len(*records) != 1 {
		t.Fatalf("got %d requests; filter must drop LOW", len(*records))
	}
}

// TestSplunkHECSink_SourceTypeOverride_Defaults verifies that every
// sink — even one built without SourceTypeOverrides — routes judge
// and verdict actions to their Phase 3 canonical sourcetypes. This is
// the load-bearing invariant for the Splunk dashboard split and for
// the E2E observability assertions (which grep for defenseclaw:judge).
func TestSplunkHECSink_SourceTypeOverride_Defaults(t *testing.T) {
	srv, records, mu, _ := httpEchoServer(t, http.StatusOK)
	sink, err := NewSplunkHECSink(SplunkHECConfig{
		Endpoint:       srv.URL,
		Token:          "t",
		BatchSize:      1,
		FlushIntervalS: 60,
	})
	if err != nil {
		t.Fatalf("NewSplunkHECSink err=%v", err)
	}
	defer sink.Close()

	cases := []struct {
		name           string
		action         string
		wantSourceType string
	}{
		{"judge routes to defenseclaw:judge", "llm-judge-response", "defenseclaw:judge"},
		{"verdict routes to defenseclaw:verdict", "guardrail-verdict", "defenseclaw:verdict"},
		{"generic audit keeps _json", "skill-scan", "_json"},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_ = sink.Forward(context.Background(), Event{
				ID:        tc.name,
				Action:    tc.action,
				Severity:  "HIGH",
				Timestamp: time.Unix(1700000000+int64(i), 0).UTC(),
			})
			mu.Lock()
			if len(*records) == 0 {
				mu.Unlock()
				t.Fatalf("no request captured for action=%s", tc.action)
			}
			body := (*records)[len(*records)-1].body
			mu.Unlock()

			var envelope struct {
				SourceType string `json:"sourcetype"`
				Event      struct {
					Action string `json:"action"`
				} `json:"event"`
			}
			if err := json.Unmarshal(body, &envelope); err != nil {
				t.Fatalf("envelope JSON: %v (%s)", err, body)
			}
			if envelope.SourceType != tc.wantSourceType {
				t.Fatalf("sourcetype=%q want %q (action=%s)",
					envelope.SourceType, tc.wantSourceType, tc.action)
			}
			if envelope.Event.Action != tc.action {
				t.Fatalf("inner action=%q want %q",
					envelope.Event.Action, tc.action)
			}
		})
	}
}

func TestSplunkHECSink_EmitsStructuredExtraHECEvents(t *testing.T) {
	testSplunkHECSinkEmitsStructuredExtraHECEvents(t, []map[string]any{
		{
			"time":       float64(1700000001),
			"source":     "otel",
			"sourcetype": "otel:log",
			"index":      "defenseclaw_local",
			"event": map[string]any{
				"session_id": "sess-1",
				"action":     "codex.user_prompt",
			},
		},
	})
}

func TestSplunkHECSink_EmitsStructuredExtraHECEventsAfterJSONClone(t *testing.T) {
	testSplunkHECSinkEmitsStructuredExtraHECEvents(t, []any{
		map[string]any{
			"time":       float64(1700000001),
			"source":     "otel",
			"sourcetype": "otel:log",
			"index":      "defenseclaw_local",
			"event": map[string]any{
				"session_id": "sess-1",
				"action":     "codex.user_prompt",
			},
		},
	})
}

func testSplunkHECSinkEmitsStructuredExtraHECEvents(t *testing.T, extraEvents any) {
	t.Helper()
	srv, records, mu, _ := httpEchoServer(t, http.StatusOK)
	sink, err := NewSplunkHECSink(SplunkHECConfig{
		Endpoint:       srv.URL,
		Token:          "t",
		BatchSize:      2,
		FlushIntervalS: 60,
	})
	if err != nil {
		t.Fatalf("NewSplunkHECSink err=%v", err)
	}
	defer sink.Close()

	err = sink.Forward(context.Background(), Event{
		ID:        "summary",
		Action:    "otel.ingest.logs",
		Severity:  "INFO",
		Timestamp: time.Unix(1700000000, 0).UTC(),
		Structured: map[string]any{
			"summary":                    "kept",
			structuredSplunkHECEventsKey: extraEvents,
		},
	})
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(*records) != 1 {
		t.Fatalf("records=%d want 1", len(*records))
	}
	dec := json.NewDecoder(strings.NewReader(string((*records)[0].body)))
	var summary struct {
		SourceType string `json:"sourcetype"`
		Event      struct {
			Action     string         `json:"action"`
			Structured map[string]any `json:"structured"`
		} `json:"event"`
	}
	if err := dec.Decode(&summary); err != nil {
		t.Fatalf("decode summary: %v", err)
	}
	if summary.SourceType != "_json" || summary.Event.Action != "otel.ingest.logs" {
		t.Fatalf("summary event wrong: %+v", summary)
	}
	if _, exists := summary.Event.Structured[structuredSplunkHECEventsKey]; exists {
		t.Fatalf("control extra-events key leaked into summary structured payload")
	}

	var logEvent struct {
		Source     string `json:"source"`
		SourceType string `json:"sourcetype"`
		Index      string `json:"index"`
		Event      struct {
			SessionID string `json:"session_id"`
			Action    string `json:"action"`
		} `json:"event"`
	}
	if err := dec.Decode(&logEvent); err != nil {
		t.Fatalf("decode otel log event: %v", err)
	}
	if logEvent.Source != "otel" || logEvent.SourceType != "otel:log" || logEvent.Index != "defenseclaw_local" {
		t.Fatalf("otel HEC envelope wrong: %+v", logEvent)
	}
	if logEvent.Event.SessionID != "sess-1" || logEvent.Event.Action != "codex.user_prompt" {
		t.Fatalf("otel HEC payload wrong: %+v", logEvent.Event)
	}
}

// TestSplunkHECSink_SourceTypeOverride_OperatorWins confirms that an
// operator-supplied override map overrides the defaults rather than
// being replaced by them. A customer who already standardised on
// `corp:llm:judge` must not be silently demoted back to
// `defenseclaw:judge`.
func TestSplunkHECSink_SourceTypeOverride_OperatorWins(t *testing.T) {
	srv, records, mu, _ := httpEchoServer(t, http.StatusOK)
	sink, err := NewSplunkHECSink(SplunkHECConfig{
		Endpoint:       srv.URL,
		Token:          "t",
		BatchSize:      1,
		FlushIntervalS: 60,
		SourceTypeOverrides: map[string]string{
			"llm-judge-response": "corp:llm:judge",
		},
	})
	if err != nil {
		t.Fatalf("NewSplunkHECSink err=%v", err)
	}
	defer sink.Close()

	_ = sink.Forward(context.Background(), Event{
		ID: "j1", Action: "llm-judge-response", Severity: "HIGH",
		Timestamp: time.Unix(1700000000, 0).UTC(),
	})

	// The defaults that the operator didn't override must still apply
	// (Phase 3 plan: defaults win unless explicitly overridden).
	_ = sink.Forward(context.Background(), Event{
		ID: "v1", Action: "guardrail-verdict", Severity: "HIGH",
		Timestamp: time.Unix(1700000001, 0).UTC(),
	})

	mu.Lock()
	defer mu.Unlock()
	if len(*records) != 2 {
		t.Fatalf("records=%d want 2", len(*records))
	}
	var first, second struct {
		SourceType string `json:"sourcetype"`
	}
	if err := json.Unmarshal((*records)[0].body, &first); err != nil {
		t.Fatalf("first envelope: %v", err)
	}
	if err := json.Unmarshal((*records)[1].body, &second); err != nil {
		t.Fatalf("second envelope: %v", err)
	}
	if first.SourceType != "corp:llm:judge" {
		t.Fatalf("operator override lost: got %q", first.SourceType)
	}
	if second.SourceType != "defenseclaw:verdict" {
		t.Fatalf("default dropped when operator override set: got %q", second.SourceType)
	}
}

// TestDefaultSourceTypeOverrides_IsIsolated guards against a subtle
// shared-map regression: callers must be able to mutate the returned
// map without leaking into other sinks. This is load-bearing when
// two sinks are constructed in sequence with different override
// policies (e.g., prod + staging in the same process).
func TestDefaultSourceTypeOverrides_IsIsolated(t *testing.T) {
	a := DefaultSourceTypeOverrides()
	b := DefaultSourceTypeOverrides()
	a["llm-judge-response"] = "mutated"
	if b["llm-judge-response"] != "defenseclaw:judge" {
		t.Fatalf("mutation leaked across callers: %q", b["llm-judge-response"])
	}
}

// TestSplunkHECSink_TLSSecureByDefault pins the F-2787 fix: a sink
// built with the zero-value config (no VerifyTLS, no
// InsecureSkipVerify) must construct an http.Client whose TLS
// transport REJECTS unverified peers. Pre-fix the same shape silently
// downgraded to InsecureSkipVerify=true and leaked the HEC token to
// any MITM peer.
func TestSplunkHECSink_TLSSecureByDefault(t *testing.T) {
	cases := []struct {
		name      string
		cfg       SplunkHECConfig
		wantSkip  bool
	}{
		{
			name:     "zero-value defaults to verify",
			cfg:      SplunkHECConfig{Endpoint: "https://splunk.example:8088", Token: "t"},
			wantSkip: false,
		},
		{
			name: "legacy verify_tls=true is honoured (no-op vs new default)",
			cfg: SplunkHECConfig{
				Endpoint: "https://splunk.example:8088", Token: "t", VerifyTLS: true,
			},
			wantSkip: false,
		},
		{
			name: "legacy verify_tls=false is IGNORED (new default wins)",
			cfg: SplunkHECConfig{
				Endpoint: "https://splunk.example:8088", Token: "t", VerifyTLS: false,
			},
			wantSkip: false,
		},
		{
			name: "explicit insecure_skip_verify=true honoured (dev opt-out)",
			cfg: SplunkHECConfig{
				Endpoint: "https://splunk.example:8088", Token: "t", InsecureSkipVerify: true,
			},
			wantSkip: true,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			sink, err := NewSplunkHECSink(tt.cfg)
			if err != nil {
				t.Fatalf("NewSplunkHECSink err=%v", err)
			}
			defer sink.Close()
			tr, ok := sink.client.Transport.(*http.Transport)
			if !ok {
				t.Fatalf("unexpected transport type %T", sink.client.Transport)
			}
			if tr.TLSClientConfig == nil {
				t.Fatal("TLSClientConfig must be set")
			}
			if got := tr.TLSClientConfig.InsecureSkipVerify; got != tt.wantSkip {
				t.Fatalf("InsecureSkipVerify=%v want %v", got, tt.wantSkip)
			}
			if tr.TLSClientConfig.MinVersion < tls.VersionTLS12 {
				t.Fatalf("MinVersion=%d must be >=TLS1.2", tr.TLSClientConfig.MinVersion)
			}
		})
	}
}

func TestSplunkHECSink_FlushEmptyIsNoop(t *testing.T) {
	srv, records, mu, _ := httpEchoServer(t, http.StatusOK)
	sink, err := NewSplunkHECSink(SplunkHECConfig{
		Endpoint: srv.URL, Token: "t", BatchSize: 10, FlushIntervalS: 60,
	})
	if err != nil {
		t.Fatalf("NewSplunkHECSink err=%v", err)
	}
	defer sink.Close()

	if err := sink.Flush(context.Background()); err != nil {
		t.Fatalf("empty Flush err=%v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if got := len(*records); got != 0 {
		t.Fatalf("empty flush generated %d requests", got)
	}
}
