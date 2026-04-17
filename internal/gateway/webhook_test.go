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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
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
	t.Setenv("DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST", "1")
	tests := []struct {
		minSeverity   string
		eventSev      string
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
	t.Setenv("DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST", "1")
	tests := []struct {
		events        []string
		action        string
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
	t.Setenv("DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST", "1")
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
		{"gateway-down", "health"},
		{"gateway-recovered", "health"},
		{"guardrail-degraded", "health"},
	}
	for _, tt := range tests {
		got := categorizeAction(tt.action)
		if got != tt.expected {
			t.Errorf("categorizeAction(%q) = %q, want %q", tt.action, got, tt.expected)
		}
	}
}

func TestFormatGenericPayloadBlockMetadata(t *testing.T) {
	evt := audit.Event{
		ID:        "evt-block-001",
		Timestamp: time.Date(2026, 4, 13, 12, 0, 0, 0, time.UTC),
		Action:    "guardrail-block",
		Target:    "gpt-4",
		Actor:     "defenseclaw-guardrail",
		Details:   "prompt injection detected",
		Severity:  "HIGH",
	}
	payload, err := formatGenericPayload(evt)
	if err != nil {
		t.Fatalf("formatGenericPayload error: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(payload, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	evtData := m["event"].(map[string]interface{})
	if evtData["defenseclaw_blocked"] != true {
		t.Errorf("expected defenseclaw_blocked=true for block action, got %v", evtData["defenseclaw_blocked"])
	}
	if evtData["defenseclaw_reason"] != "prompt injection detected" {
		t.Errorf("expected defenseclaw_reason, got %v", evtData["defenseclaw_reason"])
	}
}

func TestFormatGenericPayloadNonBlockOmitsMetadata(t *testing.T) {
	evt := audit.Event{
		ID:        "evt-drift-001",
		Timestamp: time.Date(2026, 4, 13, 12, 0, 0, 0, time.UTC),
		Action:    "drift",
		Target:    "/path/to/skill",
		Actor:     "defenseclaw-rescan",
		Details:   "hash changed",
		Severity:  "MEDIUM",
	}
	payload, err := formatGenericPayload(evt)
	if err != nil {
		t.Fatalf("formatGenericPayload error: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(payload, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	evtData := m["event"].(map[string]interface{})
	if _, ok := evtData["defenseclaw_blocked"]; ok {
		t.Error("drift event should not include defenseclaw_blocked field")
	}
}

func TestNewWebhookDispatcherSkipsDisabled(t *testing.T) {
	d := NewWebhookDispatcher([]config.WebhookConfig{
		{URL: "https://example.com", Enabled: false},
		{URL: "", Enabled: true},
	})
	if d != nil {
		t.Error("expected nil dispatcher when all endpoints are disabled/empty")
	}
}

// ---------------------------------------------------------------------------
// #1 SSRF / URL validation tests
// ---------------------------------------------------------------------------

func TestValidateWebhookURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"https valid", "https://hooks.slack.com/T/B/xxx", false},
		{"http valid", "http://example.com/webhook", false},
		{"file scheme blocked", "file:///etc/passwd", true},
		{"ftp scheme blocked", "ftp://example.com/file", true},
		{"gopher scheme blocked", "gopher://evil.com", true},
		{"private 10.x", "http://10.0.0.1/webhook", true},
		{"private 172.16.x", "http://172.16.0.1/webhook", true},
		{"private 192.168.x", "http://192.168.1.1/webhook", true},
		{"loopback 127.0.0.1", "http://127.0.0.1/webhook", true},
		{"link-local metadata", "http://169.254.169.254/latest/meta-data/", true},
		{"localhost blocked", "http://localhost/webhook", true},
		{"ipv6 loopback", "http://[::1]/webhook", true},
		{"empty hostname", "http:///path", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateWebhookURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateWebhookURL(%q) error = %v, wantErr %v", tt.url, err, tt.wantErr)
			}
		})
	}
}

func TestNewWebhookDispatcherRejectsUnsafeURL(t *testing.T) {
	d := NewWebhookDispatcher([]config.WebhookConfig{
		{URL: "http://169.254.169.254/latest/meta-data/", Type: "generic", Enabled: true},
	})
	if d != nil {
		t.Error("expected nil dispatcher when URL is private IP")
	}
}

// ---------------------------------------------------------------------------
// #2 HMAC payload signing tests
// ---------------------------------------------------------------------------

func TestHMACSignatureOnGenericEndpoint(t *testing.T) {
	t.Setenv("DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST", "1")
	var mu sync.Mutex
	var sigHeader string
	var body []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		sigHeader = r.Header.Get("X-Hub-Signature-256")
		body, _ = io.ReadAll(r.Body)
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	secret := "test-webhook-secret-42"
	t.Setenv("TEST_HMAC_SECRET", secret)

	d := NewWebhookDispatcher([]config.WebhookConfig{
		{
			URL:       srv.URL,
			Type:      "generic",
			SecretEnv: "TEST_HMAC_SECRET",
			Enabled:   true,
		},
	})

	d.Dispatch(testEvent())
	d.Close()

	mu.Lock()
	defer mu.Unlock()

	if !strings.HasPrefix(sigHeader, "sha256=") {
		t.Fatalf("expected X-Hub-Signature-256 header with sha256= prefix, got %q", sigHeader)
	}
	receivedSig := strings.TrimPrefix(sigHeader, "sha256=")

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if receivedSig != expectedSig {
		t.Errorf("HMAC mismatch: got %q, want %q", receivedSig, expectedSig)
	}
}

func TestNoSignatureWhenNoSecret(t *testing.T) {
	t.Setenv("DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST", "1")
	var mu sync.Mutex
	var sigHeader string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		sigHeader = r.Header.Get("X-Hub-Signature-256")
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewWebhookDispatcher([]config.WebhookConfig{
		{URL: srv.URL, Type: "generic", Enabled: true},
	})

	d.Dispatch(testEvent())
	d.Close()

	mu.Lock()
	defer mu.Unlock()
	if sigHeader != "" {
		t.Errorf("expected no signature header when no secret, got %q", sigHeader)
	}
}

// ---------------------------------------------------------------------------
// #3 Retry behavior: 4xx permanent vs 5xx retryable
// ---------------------------------------------------------------------------

func TestRetry4xxIsPermanent(t *testing.T) {
	t.Setenv("DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST", "1")
	statusCodes := []int{400, 401, 403, 404}

	for _, code := range statusCodes {
		t.Run(http.StatusText(code), func(t *testing.T) {
			var attempts int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&attempts, 1)
				w.WriteHeader(code)
			}))
			defer srv.Close()

			d := NewWebhookDispatcher([]config.WebhookConfig{
				{URL: srv.URL, Type: "generic", Enabled: true},
			})
			d.retryBackoff = 1 * time.Millisecond

			d.Dispatch(testEvent())
			d.Close()

			got := atomic.LoadInt32(&attempts)
			if got != 1 {
				t.Errorf("%d should be permanent failure (no retry), got %d attempts", code, got)
			}
		})
	}
}

func TestRetry5xxIsRetried(t *testing.T) {
	t.Setenv("DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST", "1")
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n <= 2 {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewWebhookDispatcher([]config.WebhookConfig{
		{URL: srv.URL, Type: "generic", Enabled: true},
	})
	d.retryBackoff = 1 * time.Millisecond

	d.Dispatch(testEvent())
	d.Close()

	got := atomic.LoadInt32(&attempts)
	if got != 3 {
		t.Errorf("expected 3 attempts (2 retries then success), got %d", got)
	}
}

func TestRetry429RespectsRetryAfter(t *testing.T) {
	t.Setenv("DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST", "1")
	start := time.Now()
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(429)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewWebhookDispatcher([]config.WebhookConfig{
		{URL: srv.URL, Type: "generic", Enabled: true},
	})
	d.retryBackoff = 1 * time.Millisecond

	d.Dispatch(testEvent())
	d.Close()

	elapsed := time.Since(start)
	got := atomic.LoadInt32(&attempts)
	if got != 2 {
		t.Errorf("expected 2 attempts, got %d", got)
	}
	if elapsed < 900*time.Millisecond {
		t.Errorf("expected Retry-After to delay ~1s, elapsed %v", elapsed)
	}
}

func TestIsRetryable(t *testing.T) {
	tests := []struct {
		status int
		want   bool
	}{
		{200, false},
		{400, false},
		{401, false},
		{403, false},
		{404, false},
		{429, true},
		{500, true},
		{502, true},
		{503, true},
	}
	for _, tt := range tests {
		got := isRetryable(tt.status)
		if got != tt.want {
			t.Errorf("isRetryable(%d) = %v, want %v", tt.status, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// #7 Event ID auto-generation
// ---------------------------------------------------------------------------

func TestDispatchAutoGeneratesEventID(t *testing.T) {
	t.Setenv("DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST", "1")
	var mu sync.Mutex
	var receivedID string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&m); err == nil {
			mu.Lock()
			if evt, ok := m["event"].(map[string]interface{}); ok {
				receivedID, _ = evt["id"].(string)
			}
			mu.Unlock()
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewWebhookDispatcher([]config.WebhookConfig{
		{URL: srv.URL, Type: "generic", MinSeverity: "INFO", Enabled: true},
	})

	evt := testEvent()
	evt.ID = "" // simulate dispatch site that forgot to set ID
	d.Dispatch(evt)
	d.Close()

	mu.Lock()
	defer mu.Unlock()
	if receivedID == "" {
		t.Error("expected auto-generated event ID, got empty string")
	}
}

// ---------------------------------------------------------------------------
// #13 Details truncation
// ---------------------------------------------------------------------------

func TestSlackDetailsTruncation(t *testing.T) {
	evt := testEvent()
	evt.Details = strings.Repeat("x", 600)

	payload, err := formatSlackPayload(evt)
	if err != nil {
		t.Fatalf("formatSlackPayload error: %v", err)
	}
	raw := string(payload)
	if !strings.Contains(raw, strings.Repeat("x", 500)+"...") {
		t.Error("expected 500 chars + ellipsis in Slack payload")
	}
	if strings.Contains(raw, strings.Repeat("x", 501)) {
		t.Error("details should be truncated at 500 chars")
	}
}

func TestWebexDetailsTruncation(t *testing.T) {
	evt := testEvent()
	evt.Details = strings.Repeat("y", 600)

	payload, err := formatWebexPayload(evt, "room-123")
	if err != nil {
		t.Fatalf("formatWebexPayload error: %v", err)
	}
	raw := string(payload)
	if !strings.Contains(raw, strings.Repeat("y", 500)+"...") {
		t.Error("expected 500 chars + ellipsis in Webex payload")
	}
}

// ---------------------------------------------------------------------------
// #5 Per-endpoint timeout
// ---------------------------------------------------------------------------

func TestPerEndpointTimeout(t *testing.T) {
	t.Setenv("DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST", "1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewWebhookDispatcher([]config.WebhookConfig{
		{URL: srv.URL, Type: "generic", Enabled: true, TimeoutSeconds: 1},
	})
	d.retryBackoff = 1 * time.Millisecond

	start := time.Now()
	d.Dispatch(testEvent())
	d.Close()
	elapsed := time.Since(start)

	if elapsed > 10*time.Second {
		t.Errorf("expected per-endpoint timeout to cap at ~1s per attempt, elapsed %v", elapsed)
	}
}

// ---------------------------------------------------------------------------
// #6 SeverityRank shared function
// ---------------------------------------------------------------------------

func TestSeverityRankShared(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"CRITICAL", 5},
		{"HIGH", 4},
		{"MEDIUM", 3},
		{"LOW", 2},
		{"INFO", 1},
		{"", 0},
		{"unknown", 0},
		{"critical", 5}, // case insensitive
	}
	for _, tt := range tests {
		got := audit.SeverityRank(tt.input)
		if got != tt.expected {
			t.Errorf("SeverityRank(%q) = %d, want %d", tt.input, got, tt.expected)
		}
	}
}

// ---------------------------------------------------------------------------
// computeHMAC
// ---------------------------------------------------------------------------

func TestComputeHMAC(t *testing.T) {
	data := []byte(`{"test": true}`)
	key := "secret123"
	got := computeHMAC(data, key)

	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(data)
	want := hex.EncodeToString(mac.Sum(nil))

	if got != want {
		t.Errorf("computeHMAC mismatch: got %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// Cooldown suppression tests
// ---------------------------------------------------------------------------

func cooldownCollector(t *testing.T) (*httptest.Server, *int32) {
	t.Helper()
	var count int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&count, 1)
		w.WriteHeader(200)
	}))
	t.Cleanup(srv.Close)
	return srv, &count
}

func cooldownDispatcher(t *testing.T, url string, cooldownSec *int) *WebhookDispatcher {
	t.Helper()
	t.Setenv("DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST", "1")
	d := NewWebhookDispatcher([]config.WebhookConfig{
		{URL: url, Type: "generic", Enabled: true, CooldownSeconds: cooldownSec},
	})
	if d != nil {
		d.retryBackoff = 0
	}
	return d
}

func TestCooldownSuppressesDuplicate(t *testing.T) {
	srv, count := cooldownCollector(t)
	d := cooldownDispatcher(t, srv.URL, intPtr(60))

	evt := testEvent()
	d.Dispatch(evt)
	d.Dispatch(evt) // same target + category, should be suppressed
	d.Close()

	if got := atomic.LoadInt32(count); got != 1 {
		t.Fatalf("expected 1 delivery (duplicate suppressed), got %d", got)
	}
}

func TestCooldownAllowsAfterExpiry(t *testing.T) {
	srv, count := cooldownCollector(t)
	d := cooldownDispatcher(t, srv.URL, intPtr(1))

	evt := testEvent()
	d.Dispatch(evt)
	d.wg.Wait()

	time.Sleep(1100 * time.Millisecond)

	d.Dispatch(evt)
	d.Close()

	if got := atomic.LoadInt32(count); got != 2 {
		t.Fatalf("expected 2 deliveries (cooldown expired), got %d", got)
	}
}

func TestCooldownZeroDisabled(t *testing.T) {
	srv, count := cooldownCollector(t)
	d := cooldownDispatcher(t, srv.URL, intPtr(0)) // explicit 0 → disabled

	evt := testEvent()
	d.Dispatch(evt)
	d.Dispatch(evt)
	d.Close()

	if got := atomic.LoadInt32(count); got != 2 {
		t.Fatalf("expected 2 deliveries (cooldown disabled), got %d", got)
	}
}

func TestCooldownDifferentTargets(t *testing.T) {
	srv, count := cooldownCollector(t)
	d := cooldownDispatcher(t, srv.URL, intPtr(60))

	evt1 := testEvent()
	evt1.Target = "skill-a"
	evt2 := testEvent()
	evt2.Target = "skill-b"

	d.Dispatch(evt1)
	d.Dispatch(evt2)
	d.Close()

	if got := atomic.LoadInt32(count); got != 2 {
		t.Fatalf("expected 2 deliveries (different targets), got %d", got)
	}
}

func TestCooldownDifferentActions(t *testing.T) {
	srv, count := cooldownCollector(t)
	d := cooldownDispatcher(t, srv.URL, intPtr(60))

	evt1 := testEvent()
	evt1.Action = "block"
	evt2 := testEvent()
	evt2.Action = "drift"

	d.Dispatch(evt1)
	d.Dispatch(evt2)
	d.Close()

	if got := atomic.LoadInt32(count); got != 2 {
		t.Fatalf("expected 2 deliveries (different categories), got %d", got)
	}
}

func TestCooldownPerEndpoint(t *testing.T) {
	srv1, count1 := cooldownCollector(t)
	srv2, count2 := cooldownCollector(t)
	t.Setenv("DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST", "1")

	d := NewWebhookDispatcher([]config.WebhookConfig{
		{URL: srv1.URL, Type: "generic", Enabled: true, CooldownSeconds: intPtr(60)},
		{URL: srv2.URL, Type: "generic", Enabled: true, CooldownSeconds: intPtr(0)}, // disabled
	})
	d.retryBackoff = 0

	evt := testEvent()
	d.Dispatch(evt)
	d.Dispatch(evt)
	d.Close()

	if got := atomic.LoadInt32(count1); got != 1 {
		t.Fatalf("endpoint 1: expected 1 delivery (cooldown active), got %d", got)
	}
	if got := atomic.LoadInt32(count2); got != 2 {
		t.Fatalf("endpoint 2: expected 2 deliveries (cooldown disabled), got %d", got)
	}
}

func TestCooldownNilDefaultsTo300(t *testing.T) {
	t.Setenv("DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST", "1")
	d := NewWebhookDispatcher([]config.WebhookConfig{
		{URL: "http://127.0.0.1:19999", Type: "generic", Enabled: true},
	})
	if d == nil {
		t.Fatal("expected non-nil dispatcher")
	}
	ep := &d.endpoints[0]
	if ep.cooldown != 300*time.Second {
		t.Errorf("expected 300s default cooldown, got %v", ep.cooldown)
	}
}

func TestCooldownHealthTransitionsNotSuppressed(t *testing.T) {
	srv, count := cooldownCollector(t)
	d := cooldownDispatcher(t, srv.URL, intPtr(60))

	down := audit.Event{
		ID: "h-1", Timestamp: time.Now(), Action: "gateway-down",
		Target: "defenseclaw-gw", Severity: "CRITICAL", Actor: "watchdog",
	}
	recovered := audit.Event{
		ID: "h-2", Timestamp: time.Now(), Action: "gateway-recovered",
		Target: "defenseclaw-gw", Severity: "INFO", Actor: "watchdog",
	}

	d.Dispatch(down)
	d.Dispatch(recovered)
	d.Close()

	if got := atomic.LoadInt32(count); got != 2 {
		t.Fatalf("expected 2 deliveries (different actions), got %d", got)
	}
}

func TestCooldownNotBurnedOnFailedSend(t *testing.T) {
	t.Setenv("DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST", "1")

	var batches int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&batches, 1)
		w.WriteHeader(500)
	}))
	defer srv.Close()

	d := NewWebhookDispatcher([]config.WebhookConfig{
		{URL: srv.URL, Type: "generic", Enabled: true, CooldownSeconds: intPtr(60)},
	})
	d.retryBackoff = 1 * time.Millisecond

	evt := testEvent()

	d.Dispatch(evt)
	d.wg.Wait()

	// First dispatch exhausted all retries and failed. The cooldown slot
	// should have been released, so the second dispatch must attempt delivery.
	d.Dispatch(evt)
	d.Close()

	got := atomic.LoadInt32(&batches)
	// 4 retries per dispatch × 2 dispatches = 8 total HTTP attempts
	if got != 8 {
		t.Fatalf("expected 8 HTTP attempts (2 full retry cycles), got %d", got)
	}
}

// TestWebhookRedactsPIIFromAllChannels proves that every webhook
// payload formatter (Slack, PagerDuty, Webex, generic) emits
// redacted content instead of raw PII. The dispatcher must scrub
// Details before calling any formatter — this test brackets all
// four paths because each builds the payload differently (Slack
// fields, PD custom_details map, Webex markdown, generic mirror).
//
// We drive the formatters via the Dispatch() entrypoint rather
// than calling them directly so the test also covers the
// belt-and-braces redaction we added at the Dispatch boundary.
func TestWebhookRedactsPIIFromAllChannels(t *testing.T) {
	t.Setenv("DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST", "1")
	t.Setenv("DEFENSECLAW_REVEAL_PII", "")

	type capture struct {
		mu     sync.Mutex
		bodies []string
	}
	caps := map[string]*capture{
		"slack":     {},
		"pagerduty": {},
		"webex":     {},
		"generic":   {},
	}
	mkSrv := func(key string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			caps[key].mu.Lock()
			caps[key].bodies = append(caps[key].bodies, string(body))
			caps[key].mu.Unlock()
			w.WriteHeader(200)
		}))
	}
	slack := mkSrv("slack")
	pd := mkSrv("pagerduty")
	webex := mkSrv("webex")
	generic := mkSrv("generic")
	defer slack.Close()
	defer pd.Close()
	defer webex.Close()
	defer generic.Close()

	d := NewWebhookDispatcher([]config.WebhookConfig{
		{URL: slack.URL, Type: "slack", Enabled: true, CooldownSeconds: intPtr(0)},
		{URL: pd.URL, Type: "pagerduty", Enabled: true, CooldownSeconds: intPtr(0)},
		{URL: webex.URL, Type: "webex", Enabled: true, CooldownSeconds: intPtr(0)},
		{URL: generic.URL, Type: "generic", Enabled: true, CooldownSeconds: intPtr(0)},
	})

	evt := audit.Event{
		ID:        "evt-pii",
		Timestamp: time.Now().UTC(),
		Action:    "block",
		Target:    "sms-tool",
		Actor:     "defenseclaw",
		// Mix of PII shapes: phone, email, SSN.
		Details:  "reason=matched secrets phone=4155551234 email=foo@example.com ssn=123-45-6789",
		Severity: "HIGH",
		RunID:    "run-pii",
	}
	d.Dispatch(evt)
	d.Close()

	pii := []string{"4155551234", "foo@example.com", "123-45-6789"}
	for channel, c := range caps {
		c.mu.Lock()
		if len(c.bodies) == 0 {
			c.mu.Unlock()
			t.Errorf("%s: no payload received", channel)
			continue
		}
		body := c.bodies[0]
		c.mu.Unlock()
		for _, needle := range pii {
			if strings.Contains(body, needle) {
				t.Errorf("%s payload leaked PII %q: %s", channel, needle, body)
			}
		}
		// A redacted payload carries "<redacted" in its Details
		// field; JSON-encoded as "\u003credacted" inside string
		// values or as "<redacted" inside Webex markdown.
		if !strings.Contains(body, "redacted len=") && !strings.Contains(body, "u003credacted") {
			t.Errorf("%s payload missing redaction marker: %s", channel, body)
		}
	}
}

// ---------------------------------------------------------------------------
// Python ↔ Go formatter parity (fixture emission)
// ---------------------------------------------------------------------------

// fixedParityEvent mirrors ``_fixed_event()`` in
// ``cli/tests/test_webhooks.py`` down to the last byte — same ID,
// timestamp, severity, action, and details string. Any drift in
// either formatter will trip this test AND the sibling Python
// ``FormatterParityTests`` since both sides pin the same structural
// invariants on the same input.
func fixedParityEvent() audit.Event {
	return audit.Event{
		ID:        "synthetic-test-fixture",
		Timestamp: time.Date(2026, 4, 14, 0, 0, 0, 0, time.UTC),
		Action:    "webhook.test",
		Target:    "synthetic-webhook",
		Actor:     "defenseclaw-cli",
		Details:   "Synthetic test event",
		Severity:  "HIGH",
	}
}

// TestFormatters_EmitCompactJSON asserts that every webhook formatter
// emits compact JSON with no trailing whitespace — the byte-for-byte
// requirement for HMAC parity between the Go dispatcher and the
// Python ``dispatch.py`` fallback. We can't just search for ``": "``
// because Slack/Webex bodies legitimately contain ``*Severity:* HIGH``
// in their markdown fields. Instead we re-parse and re-dump with
// compact separators and assert byte-equality with the original
// formatter output. This mirrors
// ``FormatterParityTests.test_compact_json_no_whitespace`` in Python.
func TestFormatters_EmitCompactJSON(t *testing.T) {
	evt := fixedParityEvent()
	cases := []struct {
		name    string
		payload []byte
		err     error
	}{}

	slackPayload, slackErr := formatSlackPayload(evt)
	cases = append(cases, struct {
		name    string
		payload []byte
		err     error
	}{"slack", slackPayload, slackErr})

	pdPayload, pdErr := formatPagerDutyPayload(evt, "routing-key")
	cases = append(cases, struct {
		name    string
		payload []byte
		err     error
	}{"pagerduty", pdPayload, pdErr})

	webexPayload, webexErr := formatWebexPayload(evt, "room-id")
	cases = append(cases, struct {
		name    string
		payload []byte
		err     error
	}{"webex", webexPayload, webexErr})

	genericPayload, genericErr := formatGenericPayload(evt)
	cases = append(cases, struct {
		name    string
		payload []byte
		err     error
	}{"generic", genericPayload, genericErr})

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.err != nil {
				t.Fatalf("formatter error: %v", tc.err)
			}
			if len(tc.payload) == 0 {
				t.Fatal("empty payload")
			}
			// Go's encoding/json never appends a trailing newline
			// from Marshal, but pin it anyway in case we ever switch
			// to Encoder.Encode (which does).
			if strings.HasSuffix(string(tc.payload), "\n") {
				t.Errorf("payload has trailing newline: %q", tc.payload)
			}

			// Round-trip parse + compact-dump must equal the
			// original bytes — this is the compact-JSON invariant.
			var v interface{}
			if err := json.Unmarshal(tc.payload, &v); err != nil {
				t.Fatalf("unmarshal: %v\npayload=%s", err, tc.payload)
			}
			roundtrip, err := json.Marshal(v)
			if err != nil {
				t.Fatalf("remarshal: %v", err)
			}
			if string(roundtrip) != string(tc.payload) {
				t.Errorf("payload is not compact JSON\n  got:     %s\n  compact: %s",
					tc.payload, roundtrip)
			}
		})
	}
}

// TestFormatters_ParityInvariants pins the same structural fields
// the Python ``FormatterParityTests`` asserts. The Python and Go
// implementations are two parallel impls of the same spec — if they
// drift, these invariants catch it on either side. Update the
// ``_fixed_event()`` helper in test_webhooks.py in lockstep when
// changing this fixture.
func TestFormatters_ParityInvariants(t *testing.T) {
	evt := fixedParityEvent()

	t.Run("slack", func(t *testing.T) {
		raw, err := formatSlackPayload(evt)
		if err != nil {
			t.Fatalf("formatSlackPayload: %v", err)
		}
		var p map[string]interface{}
		if err := json.Unmarshal(raw, &p); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		attachments, ok := p["attachments"].([]interface{})
		if !ok || len(attachments) == 0 {
			t.Fatal("expected attachments[]")
		}
		att := attachments[0].(map[string]interface{})
		// HIGH → #FF6600 — must match the Python ``_SEVERITY_COLORS``.
		if att["color"] != "#FF6600" {
			t.Errorf("HIGH color=%v want #FF6600", att["color"])
		}
		blocks, ok := att["blocks"].([]interface{})
		if !ok || len(blocks) == 0 {
			t.Fatal("expected attachment.blocks[]")
		}
		header := blocks[0].(map[string]interface{})
		if header["type"] != "header" {
			t.Errorf("block[0].type=%v want header", header["type"])
		}
		hdrText := header["text"].(map[string]interface{})["text"].(string)
		if !strings.Contains(hdrText, "webhook.test") {
			t.Errorf("header text %q missing action", hdrText)
		}
	})

	t.Run("pagerduty", func(t *testing.T) {
		raw, err := formatPagerDutyPayload(evt, "routing-xyz")
		if err != nil {
			t.Fatalf("formatPagerDutyPayload: %v", err)
		}
		var p map[string]interface{}
		if err := json.Unmarshal(raw, &p); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if p["routing_key"] != "routing-xyz" {
			t.Errorf("routing_key=%v", p["routing_key"])
		}
		if p["event_action"] != "trigger" {
			t.Errorf("event_action=%v want trigger", p["event_action"])
		}
		if _, ok := p["dedup_key"]; !ok {
			t.Error("missing dedup_key")
		}
		pd := p["payload"].(map[string]interface{})
		// HIGH maps to PD "error"; CRITICAL maps to "critical".
		if pd["severity"] != "error" {
			t.Errorf("pd severity=%v want error (HIGH)", pd["severity"])
		}
	})

	t.Run("webex", func(t *testing.T) {
		raw, err := formatWebexPayload(evt, "room-id-abc")
		if err != nil {
			t.Fatalf("formatWebexPayload: %v", err)
		}
		var p map[string]interface{}
		if err := json.Unmarshal(raw, &p); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if p["roomId"] != "room-id-abc" {
			t.Errorf("roomId=%v", p["roomId"])
		}
		md := p["markdown"].(string)
		if !strings.Contains(md, "DefenseClaw: webhook.test") {
			t.Errorf("markdown %q missing action header", md)
		}
	})

	t.Run("generic_wrapper", func(t *testing.T) {
		raw, err := formatGenericPayload(evt)
		if err != nil {
			t.Fatalf("formatGenericPayload: %v", err)
		}
		var p map[string]interface{}
		if err := json.Unmarshal(raw, &p); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if p["webhook_type"] != "defenseclaw_enforcement" {
			t.Errorf("webhook_type=%v", p["webhook_type"])
		}
		if p["defenseclaw_version"] != "1.0" {
			t.Errorf("defenseclaw_version=%v", p["defenseclaw_version"])
		}
		inner := p["event"].(map[string]interface{})
		if inner["id"] != "synthetic-test-fixture" {
			t.Errorf("event.id=%v", inner["id"])
		}
		if inner["severity"] != "HIGH" {
			t.Errorf("event.severity=%v", inner["severity"])
		}
	})

	t.Run("hmac_known_vector", func(t *testing.T) {
		// Same vector as ``test_hmac_matches_known_vector`` in
		// test_webhooks.py. Any conforming HMAC-SHA256 impl converges
		// on this hex, so a mismatch means Go or Python is broken.
		got := computeHMAC([]byte("hello world"), "k")
		const want = "67eedc5d50852aacd055cc940b52edde89eba69b15902b2a9a82483eab70d12d"
		if got != want {
			t.Errorf("computeHMAC mismatch\n  got:  %s\n  want: %s", got, want)
		}
	})
}

// TestWebhookRevealFlagDoesNotUnmaskPayloads confirms that webhooks,
// being persistent remote sinks, never honor DEFENSECLAW_REVEAL_PII.
// The reveal flag is stderr-only; anything crossing the network
// boundary must stay redacted.
func TestWebhookRevealFlagDoesNotUnmaskPayloads(t *testing.T) {
	t.Setenv("DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST", "1")
	t.Setenv("DEFENSECLAW_REVEAL_PII", "1")

	var body string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf, _ := io.ReadAll(r.Body)
		mu.Lock()
		body = string(buf)
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewWebhookDispatcher([]config.WebhookConfig{
		{URL: srv.URL, Type: "generic", Enabled: true, CooldownSeconds: intPtr(0)},
	})
	evt := audit.Event{
		Action:   "block",
		Target:   "t",
		Actor:    "defenseclaw",
		Details:  "phone=4155551234",
		Severity: "HIGH",
	}
	d.Dispatch(evt)
	d.Close()

	mu.Lock()
	defer mu.Unlock()
	if strings.Contains(body, "4155551234") {
		t.Fatalf("webhook unmasked under reveal flag: %s", body)
	}
}
