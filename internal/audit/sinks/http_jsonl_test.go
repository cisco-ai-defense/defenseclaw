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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// capturedRequest captures a single inbound POST for assertion.
type capturedRequest struct {
	method string
	path   string
	header http.Header
	body   []byte
}

func httpEchoServer(t *testing.T, status int32) (*httptest.Server, *[]capturedRequest, *sync.Mutex, *int32) {
	t.Helper()
	var (
		mu      sync.Mutex
		records []capturedRequest
		code    = status // mutable per-test
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		records = append(records, capturedRequest{
			method: r.Method,
			path:   r.URL.Path,
			header: r.Header.Clone(),
			body:   b,
		})
		mu.Unlock()
		w.WriteHeader(int(atomic.LoadInt32(&code)))
	}))
	t.Cleanup(srv.Close)
	return srv, &records, &mu, &code
}

func TestNewHTTPJSONLSink_RejectsBadURL(t *testing.T) {
	cases := []struct {
		name, url string
	}{
		{"empty", ""},
		{"missing scheme", "example.com/hook"},
		{"file scheme", "file:///tmp/out"},
		{"ftp scheme", "ftp://example.com/in"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewHTTPJSONLSink(HTTPJSONLConfig{URL: tt.url}); err == nil {
				t.Fatalf("expected error for url=%q", tt.url)
			}
		})
	}
}

func TestHTTPJSONLSink_SyncMode_PostsEach(t *testing.T) {
	srv, records, mu, _ := httpEchoServer(t, http.StatusOK)

	sink, err := NewHTTPJSONLSink(HTTPJSONLConfig{
		Name:      "vector",
		URL:       srv.URL + "/ingest",
		BatchSize: 1,
		VerifyTLS: false,
		Headers: map[string]string{
			"X-Static":   "lit",
			"X-FromEnv":  "${TEST_HEADER_VAL}",
			"X-FromCurl": "${TEST_HEADER_VAL}",
		},
	})
	if err != nil {
		t.Fatalf("NewHTTPJSONLSink err=%v", err)
	}
	t.Setenv("TEST_HEADER_VAL", "hello")
	defer sink.Close()

	ev := Event{ID: "e1", Action: "scan", Severity: "INFO",
		Timestamp: time.Unix(1700000000, 0).UTC()}
	if err := sink.Forward(context.Background(), ev); err != nil {
		t.Fatalf("Forward err=%v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if n := len(*records); n != 1 {
		t.Fatalf("server received %d requests, want 1", n)
	}
	r := (*records)[0]
	if r.method != http.MethodPost {
		t.Fatalf("method=%s want POST", r.method)
	}
	if r.path != "/ingest" {
		t.Fatalf("path=%s", r.path)
	}
	if ct := r.header.Get("Content-Type"); ct != "application/x-ndjson" {
		t.Fatalf("Content-Type=%s", ct)
	}
	if got := r.header.Get("X-Static"); got != "lit" {
		t.Fatalf("X-Static=%q", got)
	}
	if got := r.header.Get("X-Fromenv"); got != "hello" {
		t.Fatalf("env expansion failed X-FromEnv=%q", got)
	}

	var decoded Event
	if err := json.Unmarshal(r.body, &decoded); err != nil {
		t.Fatalf("body not JSON: %v (%s)", err, r.body)
	}
	if decoded.ID != "e1" {
		t.Fatalf("id=%s want e1", decoded.ID)
	}
}

func TestHTTPJSONLSink_BearerTokenAttached(t *testing.T) {
	srv, records, mu, _ := httpEchoServer(t, http.StatusOK)
	sink, err := NewHTTPJSONLSink(HTTPJSONLConfig{
		URL:         srv.URL,
		BearerToken: "sekrit",
		BatchSize:   1,
	})
	if err != nil {
		t.Fatalf("NewHTTPJSONLSink err=%v", err)
	}
	defer sink.Close()
	_ = sink.Forward(context.Background(), Event{ID: "t", Action: "a"})

	mu.Lock()
	defer mu.Unlock()
	if len(*records) != 1 {
		t.Fatal("no request observed")
	}
	if got := (*records)[0].header.Get("Authorization"); got != "Bearer sekrit" {
		t.Fatalf("Authorization=%q", got)
	}
}

func TestHTTPJSONLSink_BatchAccumulatesThenFlushesOneRequest(t *testing.T) {
	srv, records, mu, _ := httpEchoServer(t, http.StatusOK)

	sink, err := NewHTTPJSONLSink(HTTPJSONLConfig{
		URL:            srv.URL,
		BatchSize:      3,
		FlushIntervalS: 60, // do not trip the ticker mid-test
	})
	if err != nil {
		t.Fatalf("NewHTTPJSONLSink err=%v", err)
	}
	defer sink.Close()

	_ = sink.Forward(context.Background(), Event{ID: "1", Action: "a"})
	_ = sink.Forward(context.Background(), Event{ID: "2", Action: "a"})
	// After 2 forwards with batch=3 we must NOT have delivered yet.
	mu.Lock()
	if got := len(*records); got != 0 {
		t.Fatalf("delivered prematurely at size=%d", got)
	}
	mu.Unlock()

	// Third forward trips the batch — expect exactly one POST containing
	// three NDJSON lines.
	if err := sink.Forward(context.Background(), Event{ID: "3", Action: "a"}); err != nil {
		t.Fatalf("Forward err=%v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if got := len(*records); got != 1 {
		t.Fatalf("requests=%d want 1", got)
	}
	lines := strings.Count(string((*records)[0].body), "\n")
	if lines != 3 {
		t.Fatalf("NDJSON lines=%d want 3", lines)
	}
}

func TestHTTPJSONLSink_RequeuesOnFailure(t *testing.T) {
	// Start with 500 so the first flush fails → batch must be re-queued.
	srv, records, mu, code := httpEchoServer(t, http.StatusInternalServerError)

	sink, err := NewHTTPJSONLSink(HTTPJSONLConfig{
		URL:            srv.URL,
		BatchSize:      2,
		FlushIntervalS: 60,
	})
	if err != nil {
		t.Fatalf("NewHTTPJSONLSink err=%v", err)
	}
	defer sink.Close()

	_ = sink.Forward(context.Background(), Event{ID: "1", Action: "a"})
	if err := sink.Forward(context.Background(), Event{ID: "2", Action: "a"}); err == nil {
		t.Fatal("expected Forward err on 500")
	}
	// Server now becomes healthy — manual Flush must deliver the requeued
	// batch (both events) in one request.
	atomic.StoreInt32(code, http.StatusOK)
	if err := sink.Flush(context.Background()); err != nil {
		t.Fatalf("Flush err=%v after recovery", err)
	}

	mu.Lock()
	defer mu.Unlock()
	// We expect at least 2 requests (one failed, one successful). The
	// successful one must contain both events — proves requeue, not drop.
	if len(*records) < 2 {
		t.Fatalf("records=%d want >=2", len(*records))
	}
	final := (*records)[len(*records)-1]
	if !strings.Contains(string(final.body), `"id":"1"`) ||
		!strings.Contains(string(final.body), `"id":"2"`) {
		t.Fatalf("recovered request missing events: %s", final.body)
	}
}

func TestHTTPJSONLSink_FilterGatesDelivery(t *testing.T) {
	srv, records, mu, _ := httpEchoServer(t, http.StatusOK)
	sink, err := NewHTTPJSONLSink(HTTPJSONLConfig{
		URL:       srv.URL,
		BatchSize: 1,
		Filter:    SinkFilter{MinSeverity: "HIGH"},
	})
	if err != nil {
		t.Fatalf("NewHTTPJSONLSink err=%v", err)
	}
	defer sink.Close()

	_ = sink.Forward(context.Background(), Event{ID: "low", Severity: "LOW"})
	_ = sink.Forward(context.Background(), Event{ID: "hi", Severity: "CRITICAL"})

	mu.Lock()
	defer mu.Unlock()
	if len(*records) != 1 {
		t.Fatalf("got %d requests; filter must drop LOW", len(*records))
	}
	if !strings.Contains(string((*records)[0].body), `"id":"hi"`) {
		t.Fatalf("unexpected body=%s", (*records)[0].body)
	}
}

func TestExpandEnv(t *testing.T) {
	t.Setenv("DC_TEST_TOKEN", "abc123")
	t.Setenv("DC_TEST_EMPTY", "")

	cases := map[string]string{
		"literal":                  "literal",
		"${DC_TEST_TOKEN}":         "abc123",
		"Bearer ${DC_TEST_TOKEN}":  "Bearer abc123",
		"x=${DC_TEST_EMPTY}":       "x=",
		"x=${DC_UNSET_VAR_XYZZY}":  "x=",
		"mixed ${DC_TEST_TOKEN}!":  "mixed abc123!",
		"$DC_TEST_TOKEN no braces": "abc123 no braces",
	}
	for in, want := range cases {
		if got := expandEnv(in); got != want {
			t.Errorf("expandEnv(%q)=%q want %q", in, got, want)
		}
	}
}
