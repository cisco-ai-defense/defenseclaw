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

package sinks

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// HTTPJSONLConfig describes a generic webhook sink. Each event is encoded
// as a single JSON object (or batched as JSONL when batch_size > 1) and
// POSTed to URL with the configured headers.
//
// This sink is intentionally minimal so it can integrate with anything
// from a log shipper (Vector, Fluent Bit) to a custom SIEM ingest
// endpoint. For Splunk-specific HEC use SplunkHECSink; for OTLP use
// OTLPLogsSink.
type HTTPJSONLConfig struct {
	Name           string
	URL            string
	Method         string
	Headers        map[string]string
	BearerToken    string
	VerifyTLS      bool
	BatchSize      int
	FlushIntervalS int
	TimeoutS       int
	Filter         SinkFilter
}

type HTTPJSONLSink struct {
	cfg    HTTPJSONLConfig
	client *http.Client
	mu     sync.Mutex
	batch  []Event
	ticker *time.Ticker
	done   chan struct{}
}

func NewHTTPJSONLSink(cfg HTTPJSONLConfig) (*HTTPJSONLSink, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("http_jsonl: url is required")
	}
	if !strings.HasPrefix(strings.ToLower(cfg.URL), "http://") &&
		!strings.HasPrefix(strings.ToLower(cfg.URL), "https://") {
		return nil, fmt.Errorf("http_jsonl: url must be http:// or https:// (got %q)", cfg.URL)
	}
	if cfg.Method == "" {
		cfg.Method = http.MethodPost
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 1
	}
	if cfg.FlushIntervalS <= 0 {
		cfg.FlushIntervalS = 5
	}
	if cfg.TimeoutS <= 0 {
		cfg.TimeoutS = 10
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			// Mirror Splunk HEC posture: operators must explicitly set
			// verify_tls=true to enable certificate validation. The
			// generic-webhook sink commonly targets self-signed log
			// shippers in dev — flipping the default to verify=true
			// without an opt-out would break those flows.
			InsecureSkipVerify: !cfg.VerifyTLS,
			MinVersion:         tls.VersionTLS12,
		},
	}

	s := &HTTPJSONLSink{
		cfg: cfg,
		client: &http.Client{
			Transport: transport,
			Timeout:   time.Duration(cfg.TimeoutS) * time.Second,
		},
		done: make(chan struct{}),
	}

	if cfg.FlushIntervalS > 0 && cfg.BatchSize > 1 {
		s.ticker = time.NewTicker(time.Duration(cfg.FlushIntervalS) * time.Second)
		go s.flushLoop()
	}

	// Surface an explicit warning when operators point an HTTPS sink
	// at an unvalidated endpoint. The insecure default is intentional
	// (self-signed log shippers are common in dev), but silent
	// downgrade in production is a security risk — print once at boot
	// so ops sees it in the sidecar logs.
	if !cfg.VerifyTLS && strings.HasPrefix(strings.ToLower(cfg.URL), "https://") {
		fmt.Fprintf(os.Stderr,
			"warning: audit sink %q (http_jsonl): TLS certificate verification disabled for %s — set verify_tls=true for production\n",
			cfg.Name, cfg.URL)
	}

	return s, nil
}

func (s *HTTPJSONLSink) Name() string { return s.cfg.Name }
func (s *HTTPJSONLSink) Kind() string { return "http_jsonl" }

func (s *HTTPJSONLSink) Forward(ctx context.Context, e Event) error {
	if !s.cfg.Filter.Matches(e) {
		return nil
	}
	if s.cfg.BatchSize <= 1 {
		// Synchronous mode: send each event immediately. Useful for
		// low-volume audit pipelines that need real-time delivery.
		return s.send(ctx, []Event{e})
	}

	s.mu.Lock()
	s.batch = append(s.batch, e)
	needsFlush := len(s.batch) >= s.cfg.BatchSize
	s.mu.Unlock()

	if needsFlush {
		return s.Flush(ctx)
	}
	return nil
}

func (s *HTTPJSONLSink) flushLoop() {
	for {
		select {
		case <-s.ticker.C:
			_ = s.Flush(context.Background())
		case <-s.done:
			return
		}
	}
}

func (s *HTTPJSONLSink) Flush(ctx context.Context) error {
	s.mu.Lock()
	if len(s.batch) == 0 {
		s.mu.Unlock()
		return nil
	}
	pending := make([]Event, len(s.batch))
	copy(pending, s.batch)
	s.batch = s.batch[:0]
	s.mu.Unlock()

	if err := s.send(ctx, pending); err != nil {
		// Bounded retry: re-queue the failed batch so the next
		// flush attempts redelivery, but cap the queue at a
		// multiple of BatchSize so a persistently-unavailable
		// endpoint cannot grow unbounded memory. Without this cap,
		// an offline HEC/webhook collector leaks RSS until OOM.
		s.mu.Lock()
		maxQueue := maxHTTPJSONLQueue(s.cfg.BatchSize)
		combined := append(pending, s.batch...)
		if len(combined) > maxQueue {
			dropped := len(combined) - maxQueue
			fmt.Fprintf(os.Stderr,
				"warning: audit sink %q (http_jsonl): backlog cap %d reached, dropping %d oldest events\n",
				s.cfg.Name, maxQueue, dropped)
			// Keep the newest events — they are the most likely
			// to still be relevant once the endpoint recovers.
			combined = combined[len(combined)-maxQueue:]
		}
		s.batch = combined
		s.mu.Unlock()
		return err
	}
	return nil
}

// maxHTTPJSONLQueue returns the upper bound on the in-memory
// retry backlog for the webhook sink. Scaled off BatchSize so
// operators who intentionally configure small batches get a
// proportionally smaller ceiling. Minimum floor keeps the cap
// sane even for BatchSize=1.
func maxHTTPJSONLQueue(batchSize int) int {
	const (
		multiplier = 100
		floor      = 10_000
	)
	v := batchSize * multiplier
	if v < floor {
		v = floor
	}
	return v
}

func (s *HTTPJSONLSink) send(ctx context.Context, events []Event) error {
	if len(events) == 0 {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	sendCtx, cancel := context.WithTimeout(ctx, time.Duration(s.cfg.TimeoutS)*time.Second)
	defer cancel()

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, e := range events {
		if err := enc.Encode(e); err != nil {
			return fmt.Errorf("http_jsonl: encode: %w", err)
		}
	}

	req, err := http.NewRequestWithContext(sendCtx, s.cfg.Method, s.cfg.URL, bytes.NewReader(buf.Bytes()))
	if err != nil {
		return fmt.Errorf("http_jsonl: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	for k, v := range s.cfg.Headers {
		// Header values may already have been env-expanded by the config
		// layer — apply once more so direct programmatic configuration
		// still gets ${ENV} substitution.
		req.Header.Set(k, expandEnv(v))
	}
	if s.cfg.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.cfg.BearerToken)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("http_jsonl: send: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("http_jsonl: %d %s: %s", resp.StatusCode, resp.Status, string(body))
	}
	return nil
}

func (s *HTTPJSONLSink) Close() error {
	if s.ticker != nil {
		s.ticker.Stop()
	}
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	return nil
}

// expandEnv substitutes ${ENV_VAR} references inside a header value. Used
// when operators put `Authorization: Bearer ${MY_TOKEN}` in the headers
// map.
func expandEnv(v string) string {
	return os.Expand(v, func(key string) string {
		if strings.HasPrefix(key, "{") && strings.HasSuffix(key, "}") {
			key = key[1 : len(key)-1]
		}
		return os.Getenv(key)
	})
}
