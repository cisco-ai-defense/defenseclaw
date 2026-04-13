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
