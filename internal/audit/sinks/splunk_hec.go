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

// SplunkHECConfig holds Splunk HTTP Event Collector wiring for one sink.
// All fields are operator-supplied; nothing is sourced from environment
// hardcoding (token comes from cfg.Token via env-resolution at the
// config layer).
type SplunkHECConfig struct {
	Name           string
	Endpoint       string
	Token          string
	Index          string
	Source         string
	SourceType     string
	VerifyTLS      bool
	BatchSize      int
	FlushIntervalS int
	TimeoutS       int
	Filter         SinkFilter

	// SourceTypeOverrides maps a canonical audit action (e.g.
	// "llm-judge-response") to a dedicated Splunk sourcetype
	// (e.g. "defenseclaw:judge"). When an event's Action matches
	// a key, the per-event payload is emitted with the override
	// sourcetype so Splunk dashboards can segment judge/verdict
	// streams from the generic `_json` audit stream without a
	// free-form grep on the `action` field. Zero-value map means
	// "use SourceType for every event" (legacy behaviour).
	SourceTypeOverrides map[string]string
}

// DefaultSourceTypeOverrides is the canonical per-event sourcetype map
// the Phase 3 plan calls for. Operators constructing a SplunkHECConfig
// programmatically can merge this in with their own overrides; the
// config loader wires it in when the YAML block omits the explicit
// `sourcetype_overrides` map so existing installs get the judge
// split automatically without a config edit.
//
// Keeping this as a function (not a var) makes the returned map
// safe to mutate per-call without leaking into other sinks.
func DefaultSourceTypeOverrides() map[string]string {
	return map[string]string{
		// Judge events go to their own sourcetype so the Splunk
		// dashboards can pivot on model + verdict + confidence
		// without colliding with regular audit lines.
		"llm-judge-response": "defenseclaw:judge",
		// Guardrail verdicts are the single highest-value audit
		// signal for SOC teams; giving them a dedicated
		// sourcetype lets search-head admins pin retention
		// independently of the generic audit stream.
		"guardrail-verdict": "defenseclaw:verdict",
	}
}

// SplunkHECSink is the refactored Splunk HEC client extracted from the
// legacy internal/audit/splunk.go. Behaviour is intentionally identical
// (HEC event format, batching, sync flush) so existing Splunk dashboards
// keep working — the only change is config plumbing.
type SplunkHECSink struct {
	cfg    SplunkHECConfig
	client *http.Client
	mu     sync.Mutex
	batch  []splunkEvent
	ticker *time.Ticker
	done   chan struct{}
}

type splunkEvent struct {
	Time       float64 `json:"time"`
	Host       string  `json:"host,omitempty"`
	Source     string  `json:"source,omitempty"`
	SourceType string  `json:"sourcetype,omitempty"`
	Index      string  `json:"index,omitempty"`
	Event      any     `json:"event"`
}

// splunkAuditEvent is the inner payload Splunk indexes. Mirrors the
// pre-migration shape so search queries (`source=defenseclaw action=…`)
// continue to work.
type splunkAuditEvent struct {
	ID        string `json:"id"`
	Timestamp string `json:"timestamp"`
	Action    string `json:"action"`
	Target    string `json:"target"`
	Actor     string `json:"actor"`
	Details   string `json:"details"`
	Severity  string `json:"severity"`
	RunID     string `json:"run_id,omitempty"`
	Source    string `json:"source"`
	TraceID   string `json:"trace_id,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	// Extended correlation fields emitted as first-class Splunk
	// event attributes so dashboards (Splunk Local Bridge
	// macros.conf, Cisco SIEM AgentWatch) can key on them without
	// reparsing `details`. Matches the contract in sinks.Event.
	SessionID string `json:"session_id,omitempty"`
	AgentName string `json:"agent_name,omitempty"`
	// AgentID (configured logical id) and SidecarInstanceID
	// (per-process UUID) are both part of the v7 three-tier identity
	// contract and MUST reach Splunk — dashboards key on these for
	// cost attribution and incident forensics. They were omitted from
	// an earlier revision of this struct, which the I1 integration
	// test (TestCorrelation_RequestEnvelopeLandsOnAuditAndSink) now
	// pins in place.
	AgentID           string         `json:"agent_id,omitempty"`
	AgentInstanceID   string         `json:"agent_instance_id,omitempty"`
	SidecarInstanceID string         `json:"sidecar_instance_id,omitempty"`
	PolicyID          string         `json:"policy_id,omitempty"`
	DestinationApp    string         `json:"destination_app,omitempty"`
	ToolName          string         `json:"tool_name,omitempty"`
	ToolID            string         `json:"tool_id,omitempty"`
	Structured        map[string]any `json:"structured,omitempty"`
}

// NewSplunkHECSink validates config and returns a ready-to-use sink. The
// caller is responsible for registering it with the Manager.
func NewSplunkHECSink(cfg SplunkHECConfig) (*SplunkHECSink, error) {
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("splunk_hec: endpoint is required")
	}
	if cfg.Token == "" {
		return nil, fmt.Errorf("splunk_hec: token is required (set token_env or token in config)")
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 50
	}
	if cfg.FlushIntervalS <= 0 {
		cfg.FlushIntervalS = 5
	}
	if cfg.TimeoutS <= 0 {
		cfg.TimeoutS = 10
	}
	if cfg.Source == "" {
		cfg.Source = "defenseclaw"
	}
	if cfg.SourceType == "" {
		cfg.SourceType = "_json"
	}

	// Phase 3: every sink gets the canonical per-event
	// sourcetype split unless the operator has already supplied
	// their own map (which wins so customer Splunk naming
	// conventions are never overwritten). The map is cloned so
	// callers can't mutate our default after construction.
	if cfg.SourceTypeOverrides == nil {
		cfg.SourceTypeOverrides = DefaultSourceTypeOverrides()
	} else {
		merged := DefaultSourceTypeOverrides()
		for k, v := range cfg.SourceTypeOverrides {
			merged[k] = v
		}
		cfg.SourceTypeOverrides = merged
	}

	transport := &http.Transport{
		// Splunk HEC commonly runs with a self-signed cert in dev; keep
		// the same behaviour as the legacy forwarder. Operators must
		// explicitly opt in to TLS verification via verify_tls=true. This
		// is acceptable because most production deployments terminate
		// HEC behind a load balancer with a real cert.
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !cfg.VerifyTLS,
			MinVersion:         tls.VersionTLS12,
		},
	}

	s := &SplunkHECSink{
		cfg: cfg,
		client: &http.Client{
			Transport: transport,
			Timeout:   time.Duration(cfg.TimeoutS) * time.Second,
		},
		done: make(chan struct{}),
	}

	if cfg.FlushIntervalS > 0 {
		s.ticker = time.NewTicker(time.Duration(cfg.FlushIntervalS) * time.Second)
		go s.flushLoop()
	}

	// Production HEC endpoints sit behind a real certificate. Warn
	// when verify_tls is off while the endpoint scheme is https —
	// the dev-self-signed default is kept but operators should see
	// it in the boot logs so silent downgrades don't slip through
	// review. URL schemes are case-insensitive per RFC 3986 §3.1,
	// so we normalize the prefix before comparing to avoid silent
	// misses on e.g. "Https://" or "HTTPS://".
	if !cfg.VerifyTLS && strings.HasPrefix(strings.ToLower(cfg.Endpoint), "https://") {
		fmt.Fprintf(os.Stderr,
			"warning: audit sink %q (splunk_hec): TLS certificate verification disabled for %s — set verify_tls=true for production\n",
			cfg.Name, cfg.Endpoint)
	}

	return s, nil
}

func (s *SplunkHECSink) Name() string { return s.cfg.Name }
func (s *SplunkHECSink) Kind() string { return "splunk_hec" }

// sourceTypeFor picks the wire sourcetype for an event. Per-action
// overrides win over the sink-wide default so operators can keep a
// single HEC endpoint configured while still getting segmented
// streams on the Splunk side. An empty override falls through to the
// sink-wide SourceType (which itself defaults to `_json` in
// NewSplunkHECSink) — we never emit a missing/empty sourcetype on the
// wire because the HEC event format treats that as "use the HEC
// token's default", which is operator-specific and hard to audit.
func (s *SplunkHECSink) sourceTypeFor(action string, structured map[string]any) string {
	if structured != nil {
		if v, ok := structured["defenseclaw_event"].(string); ok && v == "activity" {
			return "defenseclaw:activity"
		}
	}
	if action != "" && s.cfg.SourceTypeOverrides != nil {
		if v, ok := s.cfg.SourceTypeOverrides[action]; ok && v != "" {
			return v
		}
	}
	return s.cfg.SourceType
}

func (s *SplunkHECSink) Forward(ctx context.Context, e Event) error {
	if !s.cfg.Filter.Matches(e) {
		return nil
	}
	se := splunkEvent{
		Time:       float64(e.Timestamp.Unix()) + float64(e.Timestamp.Nanosecond())/1e9,
		Source:     s.cfg.Source,
		SourceType: s.sourceTypeFor(e.Action, e.Structured),
		Index:      s.cfg.Index,
		Event: splunkAuditEvent{
			ID:                e.ID,
			Timestamp:         e.Timestamp.Format(time.RFC3339),
			Action:            e.Action,
			Target:            e.Target,
			Actor:             e.Actor,
			Details:           e.Details,
			Severity:          e.Severity,
			RunID:             e.RunID,
			Source:            "defenseclaw",
			TraceID:           e.TraceID,
			RequestID:         e.RequestID,
			SessionID:         e.SessionID,
			AgentName:         e.AgentName,
			AgentID:           e.AgentID,
			AgentInstanceID:   e.AgentInstanceID,
			SidecarInstanceID: e.SidecarInstanceID,
			PolicyID:          e.PolicyID,
			DestinationApp:    e.DestinationApp,
			ToolName:          e.ToolName,
			ToolID:            e.ToolID,
			Structured:        e.Structured,
		},
	}

	s.mu.Lock()
	s.batch = append(s.batch, se)
	needsFlush := len(s.batch) >= s.cfg.BatchSize
	s.mu.Unlock()

	if needsFlush {
		return s.Flush(ctx)
	}
	return nil
}

func (s *SplunkHECSink) flushLoop() {
	for {
		select {
		case <-s.ticker.C:
			_ = s.Flush(context.Background())
		case <-s.done:
			return
		}
	}
}

func (s *SplunkHECSink) Flush(ctx context.Context) error {
	s.mu.Lock()
	if len(s.batch) == 0 {
		s.mu.Unlock()
		return nil
	}
	pending := make([]splunkEvent, len(s.batch))
	copy(pending, s.batch)
	s.batch = s.batch[:0]
	s.mu.Unlock()

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, e := range pending {
		if err := enc.Encode(e); err != nil {
			return fmt.Errorf("splunk_hec: encode event: %w", err)
		}
	}

	if err := s.sendHEC(ctx, buf.Bytes()); err != nil {
		// Bounded retry. Re-queue the failed batch so the next
		// flush retries delivery, but cap the queue so an offline
		// HEC collector cannot grow unbounded RSS. Without this
		// cap a weekend outage ends in OOM-kill.
		s.mu.Lock()
		maxQueue := maxHECQueue(s.cfg.BatchSize)
		combined := append(pending, s.batch...)
		if len(combined) > maxQueue {
			dropped := len(combined) - maxQueue
			fmt.Fprintf(os.Stderr,
				"warning: audit sink %q (splunk_hec): backlog cap %d reached, dropping %d oldest events\n",
				s.cfg.Name, maxQueue, dropped)
			// Keep the newest events — a recovering HEC usually
			// wants the most recent signal first.
			combined = combined[len(combined)-maxQueue:]
		}
		s.batch = combined
		s.mu.Unlock()
		return err
	}
	return nil
}

// maxHECQueue returns the upper bound on the in-memory retry
// backlog for Splunk HEC. Scaled off the operator's configured
// batch size, with a floor that keeps steady-state deployments
// safe even when a small BatchSize is chosen intentionally.
func maxHECQueue(batchSize int) int {
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

func (s *SplunkHECSink) sendHEC(ctx context.Context, payload []byte) error {
	if ctx == nil {
		ctx = context.Background()
	}
	sendCtx, cancel := context.WithTimeout(ctx, time.Duration(s.cfg.TimeoutS)*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(sendCtx, http.MethodPost, s.cfg.Endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("splunk_hec: create request: %w", err)
	}
	req.Header.Set("Authorization", "Splunk "+s.cfg.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("splunk_hec: send: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("splunk_hec: HEC returned %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

func (s *SplunkHECSink) Close() error {
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
