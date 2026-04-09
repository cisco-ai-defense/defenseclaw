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
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

type SplunkConfig struct {
	HECEndpoint   string `mapstructure:"hec_endpoint"    yaml:"hec_endpoint"`
	HECToken      string `mapstructure:"hec_token"       yaml:"hec_token"`
	Index         string `mapstructure:"index"            yaml:"index"`
	Source        string `mapstructure:"source"           yaml:"source"`
	SourceType    string `mapstructure:"sourcetype"       yaml:"sourcetype"`
	VerifyTLS     bool   `mapstructure:"verify_tls"       yaml:"verify_tls"`
	Enabled       bool   `mapstructure:"enabled"          yaml:"enabled"`
	BatchSize     int    `mapstructure:"batch_size"       yaml:"batch_size"`
	FlushInterval int    `mapstructure:"flush_interval_s" yaml:"flush_interval_s"`
}

func DefaultSplunkConfig() SplunkConfig {
	return SplunkConfig{
		HECEndpoint:   "https://localhost:8088/services/collector/event",
		Index:         "defenseclaw",
		Source:        "defenseclaw",
		SourceType:    "_json",
		VerifyTLS:     false,
		Enabled:       false,
		BatchSize:     50,
		FlushInterval: 5,
	}
}

type SplunkForwarder struct {
	cfg    SplunkConfig
	client *http.Client
	mu     sync.Mutex
	batch  []splunkEvent
	ticker *time.Ticker
	done   chan struct{}
}

type splunkEvent struct {
	Time       float64     `json:"time"`
	Host       string      `json:"host,omitempty"`
	Source     string      `json:"source,omitempty"`
	SourceType string      `json:"sourcetype,omitempty"`
	Index      string      `json:"index,omitempty"`
	Event      interface{} `json:"event"`
}

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
}

func NewSplunkForwarder(cfg SplunkConfig) (*SplunkForwarder, error) {
	if cfg.HECEndpoint == "" {
		return nil, fmt.Errorf("splunk: hec_endpoint is required")
	}
	if cfg.HECToken == "" {
		return nil, fmt.Errorf("splunk: hec_token is required — set splunk.hec_token in config or DEFENSECLAW_SPLUNK_HEC_TOKEN env var")
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !cfg.VerifyTLS,
		},
	}

	f := &SplunkForwarder{
		cfg: cfg,
		client: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
		done: make(chan struct{}),
	}

	if cfg.FlushInterval > 0 {
		f.ticker = time.NewTicker(time.Duration(cfg.FlushInterval) * time.Second)
		go f.flushLoop()
	}

	return f, nil
}

func (f *SplunkForwarder) flushLoop() {
	for {
		select {
		case <-f.ticker.C:
			_ = f.Flush()
		case <-f.done:
			return
		}
	}
}

func (f *SplunkForwarder) ForwardEvent(e Event) error {
	se := splunkEvent{
		Time:       float64(e.Timestamp.Unix()) + float64(e.Timestamp.Nanosecond())/1e9,
		Source:     f.cfg.Source,
		SourceType: f.cfg.SourceType,
		Index:      f.cfg.Index,
		Event: splunkAuditEvent{
			ID:        e.ID,
			Timestamp: e.Timestamp.Format(time.RFC3339),
			Action:    e.Action,
			Target:    e.Target,
			Actor:     e.Actor,
			Details:   e.Details,
			Severity:  e.Severity,
			RunID:     e.RunID,
			Source:    "defenseclaw",
			TraceID:   e.TraceID,
		},
	}

	f.mu.Lock()
	f.batch = append(f.batch, se)
	needsFlush := len(f.batch) >= f.cfg.BatchSize
	f.mu.Unlock()

	if needsFlush {
		return f.Flush()
	}
	return nil
}

func (f *SplunkForwarder) Flush() error {
	f.mu.Lock()
	if len(f.batch) == 0 {
		f.mu.Unlock()
		return nil
	}

	pending := make([]splunkEvent, len(f.batch))
	copy(pending, f.batch)
	f.batch = f.batch[:0]
	f.mu.Unlock()

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, e := range pending {
		if err := enc.Encode(e); err != nil {
			return fmt.Errorf("splunk: encode event: %w", err)
		}
	}

	if err := f.sendHEC(buf.Bytes()); err != nil {
		f.mu.Lock()
		f.batch = append(pending, f.batch...)
		f.mu.Unlock()
		return err
	}
	return nil
}

func (f *SplunkForwarder) sendHEC(payload []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.cfg.HECEndpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("splunk: create request: %w", err)
	}
	req.Header.Set("Authorization", "Splunk "+f.cfg.HECToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := f.client.Do(req)
	if err != nil {
		return fmt.Errorf("splunk: send to HEC: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("splunk: HEC returned %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

func (f *SplunkForwarder) ExportEvents(events []Event) error {
	for _, e := range events {
		if err := f.ForwardEvent(e); err != nil {
			return err
		}
	}
	return f.Flush()
}

func (f *SplunkForwarder) Close() error {
	if f.ticker != nil {
		f.ticker.Stop()
	}
	select {
	case <-f.done:
	default:
		close(f.done)
	}
	return f.Flush()
}
