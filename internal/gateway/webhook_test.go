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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

func testEvent() audit.Event {
	return audit.Event{
		ID:        "evt-001",
		Timestamp: time.Date(2026, 4, 9, 12, 0, 0, 0, time.UTC),
		Action:    "block",
		Target:    "malicious-skill",
		Actor:     "defenseclaw-watcher",
		Details:   "type=skill severity=HIGH findings=3 actions=quarantined,blocked reason=malware detected",
		Severity:  "HIGH",
		RunID:     "run-123",
	}
}

func TestFormatSlackPayload(t *testing.T) {
	payload, err := formatSlackPayload(testEvent())
	if err != nil {
		t.Fatalf("formatSlackPayload error: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(payload, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	attachments, ok := m["attachments"].([]interface{})
	if !ok || len(attachments) == 0 {
		t.Fatal("expected attachments array")
	}
	att := attachments[0].(map[string]interface{})
	if att["color"] != "#FF6600" {
		t.Errorf("expected HIGH color #FF6600, got %s", att["color"])
	}
}

func TestFormatPagerDutyPayload(t *testing.T) {
	payload, err := formatPagerDutyPayload(testEvent(), "test-routing-key")
	if err != nil {
		t.Fatalf("formatPagerDutyPayload error: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(payload, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["routing_key"] != "test-routing-key" {
		t.Errorf("expected routing_key=test-routing-key, got %v", m["routing_key"])
	}
	if m["event_action"] != "trigger" {
		t.Errorf("expected event_action=trigger, got %v", m["event_action"])
	}
	p := m["payload"].(map[string]interface{})
	if p["severity"] != "error" {
		t.Errorf("expected PD severity=error for HIGH, got %v", p["severity"])
	}
}

func TestFormatWebexPayload(t *testing.T) {
	payload, err := formatWebexPayload(testEvent(), "Y2lzY29zcGFyazovL3VzL1JPT00vdGVzdC1yb29t")
	if err != nil {
		t.Fatalf("formatWebexPayload error: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(payload, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["roomId"] != "Y2lzY29zcGFyazovL3VzL1JPT00vdGVzdC1yb29t" {
		t.Errorf("expected roomId to match, got %v", m["roomId"])
	}
	md, ok := m["markdown"].(string)
	if !ok || md == "" {
		t.Fatal("expected non-empty markdown field")
	}
	if !strings.Contains(md, "DefenseClaw: block") {
		t.Errorf("markdown should contain action, got %q", md)
	}
	if !strings.Contains(md, "malicious-skill") {
		t.Errorf("markdown should contain target, got %q", md)
	}
	if !strings.Contains(md, "HIGH") {
		t.Errorf("markdown should contain severity, got %q", md)
	}
}

func TestFormatGenericPayload(t *testing.T) {
	payload, err := formatGenericPayload(testEvent())
	if err != nil {
		t.Fatalf("formatGenericPayload error: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(payload, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["webhook_type"] != "defenseclaw_enforcement" {
		t.Errorf("expected webhook_type=defenseclaw_enforcement, got %v", m["webhook_type"])
	}
	evt := m["event"].(map[string]interface{})
	if evt["action"] != "block" {
		t.Errorf("expected action=block, got %v", evt["action"])
	}
}

func TestSeverityFiltering(t *testing.T) {
	tests := []struct {
		minSeverity  string
		eventSev     string
		shouldDeliver bool
	}{
		{"HIGH", "CRITICAL", true},
		{"HIGH", "HIGH", true},
		{"HIGH", "MEDIUM", false},
		{"HIGH", "LOW", false},
		{"MEDIUM", "HIGH", true},
		{"CRITICAL", "HIGH", false},
	}

	for _, tt := range tests {
		t.Run(tt.minSeverity+"_"+tt.eventSev, func(t *testing.T) {
			var mu sync.Mutex
			received := false
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				received = true
				mu.Unlock()
				w.WriteHeader(200)
			}))
			defer srv.Close()

			d := NewWebhookDispatcher([]config.WebhookConfig{
				{
					URL:         srv.URL,
					Type:        "generic",
					MinSeverity: tt.minSeverity,
					Enabled:     true,
				},
			})
			evt := testEvent()
			evt.Severity = tt.eventSev
			d.Dispatch(evt)
			d.Close()

			mu.Lock()
			got := received
			mu.Unlock()
			if got != tt.shouldDeliver {
				t.Errorf("minSeverity=%s eventSev=%s: expected delivered=%v, got %v",
					tt.minSeverity, tt.eventSev, tt.shouldDeliver, got)
			}
		})
	}
}

func TestEventTypeFiltering(t *testing.T) {
	tests := []struct {
		events       []string
		action       string
		shouldDeliver bool
	}{
		{[]string{"block"}, "block", true},
		{[]string{"block"}, "drift", false},
		{[]string{"drift"}, "drift", true},
		{[]string{"guardrail"}, "guardrail-block", true},
		{[]string{"block", "drift"}, "drift", true},
		{[]string{}, "block", true}, // empty = all events
	}

	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			var mu sync.Mutex
			received := false
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				received = true
				mu.Unlock()
				w.WriteHeader(200)
			}))
			defer srv.Close()

			d := NewWebhookDispatcher([]config.WebhookConfig{
				{
					URL:         srv.URL,
					Type:        "generic",
					MinSeverity: "INFO",
					Events:      tt.events,
					Enabled:     true,
				},
			})
			evt := testEvent()
			evt.Action = tt.action
			d.Dispatch(evt)
			d.Close()

			mu.Lock()
			got := received
			mu.Unlock()
			if got != tt.shouldDeliver {
				t.Errorf("events=%v action=%s: expected delivered=%v, got %v",
					tt.events, tt.action, tt.shouldDeliver, got)
			}
		})
	}
}

func TestWebhookDispatch_Integration(t *testing.T) {
	var mu sync.Mutex
	var payloads []map[string]interface{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&m); err == nil {
			mu.Lock()
			payloads = append(payloads, m)
			mu.Unlock()
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewWebhookDispatcher([]config.WebhookConfig{
		{
			URL:         srv.URL,
			Type:        "generic",
			MinSeverity: "INFO",
			Enabled:     true,
		},
	})

	d.Dispatch(testEvent())
	d.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(payloads) != 1 {
		t.Fatalf("expected 1 payload, got %d", len(payloads))
	}
	if payloads[0]["webhook_type"] != "defenseclaw_enforcement" {
		t.Errorf("expected webhook_type=defenseclaw_enforcement, got %v", payloads[0]["webhook_type"])
	}
}

func TestWebhookDispatcherNil(t *testing.T) {
	var d *WebhookDispatcher
	d.Dispatch(testEvent()) // should not panic
	d.Close()               // should not panic
}

func TestCategorizeAction(t *testing.T) {
	tests := []struct {
		action   string
		expected string
	}{
		{"block", "block"},
		{"quarantine", "block"},
		{"sidecar-watcher-disable", "block"},
		{"drift", "drift"},
		{"rescan", "drift"},
		{"guardrail-block", "guardrail"},
		{"guardrail-inspection", "guardrail"},
		{"scan", "scan"},
		{"init", "init"},
	}
	for _, tt := range tests {
		got := categorizeAction(tt.action)
		if got != tt.expected {
			t.Errorf("categorizeAction(%q) = %q, want %q", tt.action, got, tt.expected)
		}
	}
}

func TestNewWebhookDispatcherSkipsDisabled(t *testing.T) {
	d := NewWebhookDispatcher([]config.WebhookConfig{
		{URL: "http://example.com", Enabled: false},
		{URL: "", Enabled: true},
	})
	if d != nil {
		t.Error("expected nil dispatcher when all endpoints are disabled/empty")
	}
}
