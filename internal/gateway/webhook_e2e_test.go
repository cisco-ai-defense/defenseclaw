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

// receivedPayload captures both the raw JSON and the HTTP request metadata.
type receivedPayload struct {
	Body        map[string]interface{}
	ContentType string
	SecretHdr   string
	Method      string
}

// webhookCollector is a test HTTP server that captures incoming payloads
// with full request metadata for validation.
type webhookCollector struct {
	mu       sync.Mutex
	payloads []receivedPayload
	srv      *httptest.Server
	statusFn func(n int) int // optional: return status based on attempt number
}

func newCollector() *webhookCollector {
	c := &webhookCollector{}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&m)
		c.mu.Lock()
		n := len(c.payloads)
		c.payloads = append(c.payloads, receivedPayload{
			Body:        m,
			ContentType: r.Header.Get("Content-Type"),
			SecretHdr:   r.Header.Get("X-Webhook-Secret"),
			Method:      r.Method,
		})
		statusFn := c.statusFn
		c.mu.Unlock()
		status := 200
		if statusFn != nil {
			status = statusFn(n + 1)
		}
		w.WriteHeader(status)
	}))
	return c
}

func (c *webhookCollector) Close()                  { c.srv.Close() }
func (c *webhookCollector) URL() string             { return c.srv.URL }
func (c *webhookCollector) get() []receivedPayload  { c.mu.Lock(); defer c.mu.Unlock(); cp := make([]receivedPayload, len(c.payloads)); copy(cp, c.payloads); return cp }
func (c *webhookCollector) count() int              { c.mu.Lock(); defer c.mu.Unlock(); return len(c.payloads) }

// newTestDispatcher creates a WebhookDispatcher with zero retry backoff for fast tests.
func newTestDispatcher(cfgs []config.WebhookConfig) *WebhookDispatcher {
	d := NewWebhookDispatcher(cfgs)
	if d != nil {
		d.retryBackoff = 0 // no wait between retries in tests
	}
	return d
}

// ---------------------------------------------------------------------------
// Full realistic E2E test: multi-event enforcement pipeline
// ---------------------------------------------------------------------------

// TestWebhookE2E_FullEnforcementPipeline simulates the complete DefenseClaw
// enforcement pipeline — watcher blocks a malicious skill, rescan detects
// drift, guardrail blocks a prompt injection — and verifies that each event
// is delivered to the correct webhook endpoints with correct payloads.
func TestWebhookE2E_FullEnforcementPipeline(t *testing.T) {
	// --- Set up 3 simulated external webhook receivers ---
	slackReceiver := newCollector()
	defer slackReceiver.Close()

	pagerdutyReceiver := newCollector()
	defer pagerdutyReceiver.Close()
	pagerdutyReceiver.statusFn = func(int) int { return 202 } // PD returns 202 Accepted

	genericReceiver := newCollector()
	defer genericReceiver.Close()

	// --- Create dispatcher with realistic multi-endpoint config ---
	d := newTestDispatcher([]config.WebhookConfig{
		{
			URL:         slackReceiver.URL(),
			Type:        "slack",
			MinSeverity: "MEDIUM",
			Events:      []string{"block", "drift", "guardrail"},
			Enabled:     true,
		},
		{
			URL:         pagerdutyReceiver.URL(),
			Type:        "pagerduty",
			MinSeverity: "HIGH",
			Events:      []string{"block"},
			Enabled:     true,
		},
		{
			URL:            genericReceiver.URL(),
			Type:           "generic",
			SecretEnv:      "",
			MinSeverity:    "INFO",
			Events:         []string{"block", "drift", "guardrail", "scan"},
			TimeoutSeconds: 5,
			Enabled:        true,
		},
	})
	if d == nil {
		t.Fatal("expected non-nil dispatcher")
	}

	// ── EVENT 1: Watcher blocks a malicious skill ──
	// Simulates sendEnforcementAlert in sidecar.go creating this event
	skillBlockEvent := audit.Event{
		ID:        "evt-watcher-001",
		Timestamp: time.Now().UTC(),
		Action:    "block",
		Target:    "crypto-miner-skill",
		Actor:     "defenseclaw-watcher",
		Details:   "type=skill severity=CRITICAL findings=7 actions=quarantined,blocked,disabled reason=malware signature detected in node_modules",
		Severity:  "CRITICAL",
		RunID:     "run-e2e-pipeline",
	}
	d.Dispatch(skillBlockEvent)

	// ── EVENT 2: Drift detected during periodic rescan ──
	// Simulates emitDriftAlerts in rescan.go
	driftEvent := audit.Event{
		ID:        "evt-drift-002",
		Timestamp: time.Now().UTC(),
		Action:    "drift",
		Target:    "/home/user/.openclaw/workspace/skills/data-analyzer",
		Actor:     "defenseclaw-rescan",
		Details:   `[{"type":"dependency_change","severity":"MEDIUM","description":"dependency manifest modified: package.json"},{"type":"new_endpoint","severity":"HIGH","description":"new network endpoint detected: https://evil-c2.example.com/exfil"}]`,
		Severity:  "HIGH",
	}
	d.Dispatch(driftEvent)

	// ── EVENT 3: Guardrail blocks a prompt injection ──
	// Simulates recordTelemetry in proxy.go when verdict.Action == "block"
	guardrailBlockEvent := audit.Event{
		ID:        "evt-guardrail-003",
		Timestamp: time.Now().UTC(),
		Action:    "guardrail-block",
		Target:    "anthropic/claude-sonnet-4-20250514",
		Actor:     "defenseclaw-guardrail",
		Details:   "direction=prompt action=block severity=HIGH findings=2 elapsed_ms=45.3 reason=prompt_injection:ignore_previous_instructions",
		Severity:  "HIGH",
	}
	d.Dispatch(guardrailBlockEvent)

	// ── EVENT 4: Low-severity scan (should only reach generic) ──
	scanEvent := audit.Event{
		ID:        "evt-scan-004",
		Timestamp: time.Now().UTC(),
		Action:    "scan",
		Target:    "safe-utility-skill",
		Actor:     "defenseclaw",
		Details:   "scanner=skill-scanner findings=0 max_severity=INFO",
		Severity:  "INFO",
	}
	d.Dispatch(scanEvent)

	// Wait for all async sends to complete
	d.Close()

	// --- Validate Slack endpoint ---
	// Slack: min_severity=MEDIUM, events=[block, drift, guardrail]
	// Should receive: skill block (CRITICAL ≥ MEDIUM), drift (HIGH ≥ MEDIUM), guardrail (HIGH ≥ MEDIUM)
	// Should NOT receive: scan (INFO < MEDIUM, and scan not in event filter)
	slackPayloads := slackReceiver.get()
	if len(slackPayloads) != 3 {
		t.Errorf("[slack] expected 3 payloads (block+drift+guardrail), got %d", len(slackPayloads))
	}
	for _, p := range slackPayloads {
		if p.ContentType != "application/json" {
			t.Errorf("[slack] expected Content-Type=application/json, got %q", p.ContentType)
		}
		if p.Method != "POST" {
			t.Errorf("[slack] expected POST, got %s", p.Method)
		}
		attachments, ok := p.Body["attachments"].([]interface{})
		if !ok || len(attachments) == 0 {
			t.Error("[slack] missing attachments array")
			continue
		}
		att := attachments[0].(map[string]interface{})
		color, _ := att["color"].(string)
		if color == "" {
			t.Error("[slack] missing color on attachment")
		}
		blocks, _ := att["blocks"].([]interface{})
		if len(blocks) < 3 {
			t.Errorf("[slack] expected ≥3 blocks (header, section, context), got %d", len(blocks))
		}
	}

	// Validate that at least one Slack payload has CRITICAL red color
	foundCriticalRed := false
	for _, p := range slackPayloads {
		att := p.Body["attachments"].([]interface{})[0].(map[string]interface{})
		if att["color"] == "#FF0000" {
			foundCriticalRed = true
			break
		}
	}
	if !foundCriticalRed {
		t.Error("[slack] expected at least one CRITICAL payload with red (#FF0000) color")
	}

	// --- Validate PagerDuty endpoint ---
	// PagerDuty: min_severity=HIGH, events=[block]
	// Should receive: skill block (CRITICAL ≥ HIGH, action=block)
	// Should NOT receive: drift (HIGH ≥ HIGH but action=drift not in filter), guardrail, scan
	pdPayloads := pagerdutyReceiver.get()
	if len(pdPayloads) != 1 {
		t.Errorf("[pagerduty] expected 1 payload (block only), got %d", len(pdPayloads))
	}
	if len(pdPayloads) >= 1 {
		pd := pdPayloads[0]
		if pd.ContentType != "application/json" {
			t.Errorf("[pagerduty] expected Content-Type=application/json, got %q", pd.ContentType)
		}
		body := pd.Body
		if body["event_action"] != "trigger" {
			t.Errorf("[pagerduty] expected event_action=trigger, got %v", body["event_action"])
		}
		dedupKey, _ := body["dedup_key"].(string)
		if !strings.Contains(dedupKey, "crypto-miner-skill") {
			t.Errorf("[pagerduty] dedup_key should contain target name, got %q", dedupKey)
		}
		payload := body["payload"].(map[string]interface{})
		if payload["severity"] != "critical" {
			t.Errorf("[pagerduty] expected severity=critical for CRITICAL event, got %v", payload["severity"])
		}
		if payload["source"] != "defenseclaw" {
			t.Errorf("[pagerduty] expected source=defenseclaw, got %v", payload["source"])
		}
		summary, _ := payload["summary"].(string)
		if !strings.Contains(summary, "crypto-miner-skill") {
			t.Errorf("[pagerduty] summary should mention target, got %q", summary)
		}
		customDetails := payload["custom_details"].(map[string]interface{})
		if customDetails["action"] != "block" {
			t.Errorf("[pagerduty] custom_details.action should be block, got %v", customDetails["action"])
		}
		if customDetails["event_id"] != "evt-watcher-001" {
			t.Errorf("[pagerduty] custom_details.event_id should be evt-watcher-001, got %v", customDetails["event_id"])
		}
	}

	// --- Validate Generic endpoint ---
	// Generic: min_severity=INFO, events=[block, drift, guardrail, scan]
	// Should receive ALL 4 events
	genPayloads := genericReceiver.get()
	if len(genPayloads) != 4 {
		t.Errorf("[generic] expected 4 payloads (block+drift+guardrail+scan), got %d", len(genPayloads))
	}

	// Index generic payloads by event ID for order-independent assertions
	byID := make(map[string]receivedPayload)
	for _, p := range genPayloads {
		if p.Body["webhook_type"] != "defenseclaw_enforcement" {
			t.Errorf("[generic] expected webhook_type=defenseclaw_enforcement, got %v", p.Body["webhook_type"])
		}
		if p.Body["defenseclaw_version"] != "1.0" {
			t.Errorf("[generic] expected defenseclaw_version=1.0, got %v", p.Body["defenseclaw_version"])
		}
		evt := p.Body["event"].(map[string]interface{})
		if _, ok := evt["timestamp"]; !ok {
			t.Error("[generic] missing timestamp")
		}
		id, _ := evt["id"].(string)
		byID[id] = p
	}

	// Validate the watcher block event
	if p, ok := byID["evt-watcher-001"]; ok {
		e := p.Body["event"].(map[string]interface{})
		if e["action"] != "block" {
			t.Errorf("[generic][block] action should be block, got %v", e["action"])
		}
		if e["target"] != "crypto-miner-skill" {
			t.Errorf("[generic][block] target should be crypto-miner-skill, got %v", e["target"])
		}
		if e["severity"] != "CRITICAL" {
			t.Errorf("[generic][block] severity should be CRITICAL, got %v", e["severity"])
		}
		if e["actor"] != "defenseclaw-watcher" {
			t.Errorf("[generic][block] actor should be defenseclaw-watcher, got %v", e["actor"])
		}
		if e["run_id"] != "run-e2e-pipeline" {
			t.Errorf("[generic][block] run_id should be run-e2e-pipeline, got %v", e["run_id"])
		}
	} else {
		t.Error("[generic] missing evt-watcher-001 (block event)")
	}

	// Validate the drift event
	if p, ok := byID["evt-drift-002"]; ok {
		e := p.Body["event"].(map[string]interface{})
		if e["action"] != "drift" {
			t.Errorf("[generic][drift] action should be drift, got %v", e["action"])
		}
		details, _ := e["details"].(string)
		if !strings.Contains(details, "dependency_change") {
			t.Errorf("[generic][drift] details should contain drift delta JSON, got %q", details)
		}
	} else {
		t.Error("[generic] missing evt-drift-002 (drift event)")
	}

	// Validate the guardrail block event
	if p, ok := byID["evt-guardrail-003"]; ok {
		e := p.Body["event"].(map[string]interface{})
		if e["action"] != "guardrail-block" {
			t.Errorf("[generic][guardrail] action should be guardrail-block, got %v", e["action"])
		}
		if e["actor"] != "defenseclaw-guardrail" {
			t.Errorf("[generic][guardrail] actor should be defenseclaw-guardrail, got %v", e["actor"])
		}
	} else {
		t.Error("[generic] missing evt-guardrail-003 (guardrail-block event)")
	}

	// Validate the scan event
	if p, ok := byID["evt-scan-004"]; ok {
		e := p.Body["event"].(map[string]interface{})
		if e["action"] != "scan" {
			t.Errorf("[generic][scan] action should be scan, got %v", e["action"])
		}
		if e["severity"] != "INFO" {
			t.Errorf("[generic][scan] severity should be INFO, got %v", e["severity"])
		}
	} else {
		t.Error("[generic] missing evt-scan-004 (scan event)")
	}
}

// ---------------------------------------------------------------------------
// Retry under transient failures
// ---------------------------------------------------------------------------

// TestWebhookE2E_RetryOnTransientFailure verifies the dispatcher retries
// on 503/500 responses and eventually delivers the payload.
func TestWebhookE2E_RetryOnTransientFailure(t *testing.T) {
	receiver := newCollector()
	defer receiver.Close()
	// First 2 attempts return 503, third succeeds
	receiver.statusFn = func(n int) int {
		if n <= 2 {
			return 503
		}
		return 200
	}

	d := newTestDispatcher([]config.WebhookConfig{
		{URL: receiver.URL(), Type: "generic", MinSeverity: "INFO", Enabled: true},
	})

	d.Dispatch(testEvent())
	d.Close()

	got := receiver.count()
	if got < 3 {
		t.Errorf("expected at least 3 attempts (initial + 2 retries), got %d", got)
	}

	// The last payload should be the successful one with correct content
	payloads := receiver.get()
	last := payloads[len(payloads)-1]
	if last.Body["webhook_type"] != "defenseclaw_enforcement" {
		t.Errorf("final payload should be valid generic format")
	}
}

// TestWebhookE2E_AllRetriesExhausted verifies that when all retries fail,
// the dispatcher does not panic and the payload structure is still correct.
func TestWebhookE2E_AllRetriesExhausted(t *testing.T) {
	receiver := newCollector()
	defer receiver.Close()
	receiver.statusFn = func(int) int { return 500 } // always fail

	d := newTestDispatcher([]config.WebhookConfig{
		{URL: receiver.URL(), Type: "generic", MinSeverity: "INFO", Enabled: true},
	})

	d.Dispatch(testEvent())
	d.Close() // should not hang

	got := receiver.count()
	expected := webhookMaxRetries + 1 // initial + retries
	if got != expected {
		t.Errorf("expected %d total attempts, got %d", expected, got)
	}
}

// ---------------------------------------------------------------------------
// Secret header on generic webhooks
// ---------------------------------------------------------------------------

// TestWebhookE2E_GenericSecretHeader verifies that X-Webhook-Secret is
// set on generic webhook requests when a secret is configured.
func TestWebhookE2E_GenericSecretHeader(t *testing.T) {
	receiver := newCollector()
	defer receiver.Close()

	t.Setenv("TEST_WEBHOOK_SECRET_E2E", "supersecretvalue42")

	d := newTestDispatcher([]config.WebhookConfig{
		{
			URL:       receiver.URL(),
			Type:      "generic",
			SecretEnv: "TEST_WEBHOOK_SECRET_E2E",
			Enabled:   true,
		},
	})

	d.Dispatch(testEvent())
	d.Close()

	payloads := receiver.get()
	if len(payloads) != 1 {
		t.Fatalf("expected 1 payload, got %d", len(payloads))
	}
	if payloads[0].SecretHdr != "supersecretvalue42" {
		t.Errorf("expected X-Webhook-Secret=supersecretvalue42, got %q", payloads[0].SecretHdr)
	}
}

// TestWebhookE2E_SlackNoSecretHeader verifies that X-Webhook-Secret is
// NOT sent for Slack webhooks (Slack authenticates via the URL token).
func TestWebhookE2E_SlackNoSecretHeader(t *testing.T) {
	receiver := newCollector()
	defer receiver.Close()

	d := newTestDispatcher([]config.WebhookConfig{
		{URL: receiver.URL(), Type: "slack", Enabled: true},
	})

	d.Dispatch(testEvent())
	d.Close()

	payloads := receiver.get()
	if len(payloads) != 1 {
		t.Fatalf("expected 1 payload, got %d", len(payloads))
	}
	if payloads[0].SecretHdr != "" {
		t.Errorf("slack webhooks should not include X-Webhook-Secret, got %q", payloads[0].SecretHdr)
	}
}

// ---------------------------------------------------------------------------
// Severity threshold edge cases
// ---------------------------------------------------------------------------

// TestWebhookE2E_SeverityEdgeCases verifies boundary behavior for severity
// filtering across all severity levels.
func TestWebhookE2E_SeverityEdgeCases(t *testing.T) {
	severities := []string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

	for _, threshold := range severities {
		for _, eventSev := range severities {
			name := threshold + "_accepts_" + eventSev
			t.Run(name, func(t *testing.T) {
				receiver := newCollector()
				defer receiver.Close()

				d := newTestDispatcher([]config.WebhookConfig{
					{URL: receiver.URL(), Type: "generic", MinSeverity: threshold, Enabled: true},
				})

				evt := testEvent()
				evt.Severity = eventSev
				d.Dispatch(evt)
				d.Close()

				delivered := receiver.count() > 0
				expected := severityToRank(eventSev) >= severityToRank(threshold)
				if delivered != expected {
					t.Errorf("threshold=%s event=%s: delivered=%v, want %v",
						threshold, eventSev, delivered, expected)
				}
			})
		}
	}
}

// ---------------------------------------------------------------------------
// Mixed enabled/disabled endpoints
// ---------------------------------------------------------------------------

// TestWebhookE2E_MixedEnabledDisabled verifies that disabled endpoints
// are silently skipped and enabled ones still receive events.
func TestWebhookE2E_MixedEnabledDisabled(t *testing.T) {
	activeReceiver := newCollector()
	defer activeReceiver.Close()

	disabledReceiver := newCollector()
	defer disabledReceiver.Close()

	d := newTestDispatcher([]config.WebhookConfig{
		{URL: disabledReceiver.URL(), Type: "generic", Enabled: false},
		{URL: activeReceiver.URL(), Type: "generic", Enabled: true},
		{URL: "", Type: "generic", Enabled: true},
	})

	d.Dispatch(testEvent())
	d.Close()

	if activeReceiver.count() != 1 {
		t.Errorf("active endpoint should receive 1 payload, got %d", activeReceiver.count())
	}
	if disabledReceiver.count() != 0 {
		t.Errorf("disabled endpoint should receive 0 payloads, got %d", disabledReceiver.count())
	}
}

// ---------------------------------------------------------------------------
// Concurrent dispatch safety
// ---------------------------------------------------------------------------

// TestWebhookE2E_ConcurrentDispatch verifies that dispatching many events
// concurrently does not cause races or lost payloads.
func TestWebhookE2E_ConcurrentDispatch(t *testing.T) {
	receiver := newCollector()
	defer receiver.Close()

	d := newTestDispatcher([]config.WebhookConfig{
		{URL: receiver.URL(), Type: "generic", MinSeverity: "INFO", Enabled: true},
	})

	const numEvents = 50
	var wg sync.WaitGroup
	for i := 0; i < numEvents; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			evt := audit.Event{
				ID:        time.Now().Format("20060102150405.000000") + "-" + string(rune('A'+i%26)),
				Timestamp: time.Now().UTC(),
				Action:    "block",
				Target:    "concurrent-skill",
				Actor:     "test",
				Severity:  "HIGH",
			}
			d.Dispatch(evt)
		}(i)
	}
	wg.Wait()
	d.Close()

	got := receiver.count()
	if got != numEvents {
		t.Errorf("expected %d payloads for concurrent dispatch, got %d", numEvents, got)
	}
}

// ---------------------------------------------------------------------------
// Post-close dispatch is silently dropped
// ---------------------------------------------------------------------------

// TestWebhookE2E_DispatchAfterClose verifies that events sent after Close
// are silently dropped without panic.
func TestWebhookE2E_DispatchAfterClose(t *testing.T) {
	receiver := newCollector()
	defer receiver.Close()

	d := newTestDispatcher([]config.WebhookConfig{
		{URL: receiver.URL(), Type: "generic", Enabled: true},
	})

	d.Dispatch(testEvent())
	d.Close()

	before := receiver.count()

	// These should be silently dropped
	d.Dispatch(testEvent())
	d.Dispatch(testEvent())
	time.Sleep(50 * time.Millisecond)

	after := receiver.count()
	if after != before {
		t.Errorf("expected no new payloads after Close, before=%d after=%d", before, after)
	}
}
