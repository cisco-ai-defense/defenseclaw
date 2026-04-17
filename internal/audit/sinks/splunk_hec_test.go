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
	_ = sink.Forward(context.Background(),
		Event{ID: "verdict-1", Action: "guardrail-verdict",
			Severity: "HIGH", Timestamp: time.Unix(1700000000, 0).UTC(),
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
			ID         string         `json:"id"`
			Action     string         `json:"action"`
			Severity   string         `json:"severity"`
			Structured map[string]any `json:"structured"`
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
	if envelope.Event.ID != "verdict-1" || envelope.Event.Action != "guardrail-verdict" {
		t.Fatalf("inner event wrong: %+v", envelope.Event)
	}
	if envelope.Event.Structured["stage"] != "guardrail" {
		t.Fatalf("structured dropped: %+v", envelope.Event.Structured)
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
