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
	"os"
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
	SigHdr      string // X-Hub-Signature-256
	AuthHdr     string
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
			SigHdr:      r.Header.Get("X-Hub-Signature-256"),
			AuthHdr:     r.Header.Get("Authorization"),
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

func (c *webhookCollector) Close()                 { c.srv.Close() }
func (c *webhookCollector) URL() string            { return c.srv.URL }
func (c *webhookCollector) get() []receivedPayload { c.mu.Lock(); defer c.mu.Unlock(); cp := make([]receivedPayload, len(c.payloads)); copy(cp, c.payloads); return cp }
func (c *webhookCollector) count() int             { c.mu.Lock(); defer c.mu.Unlock(); return len(c.payloads) }

// newTestDispatcher creates a WebhookDispatcher with zero retry backoff for fast tests.
// It sets DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST=1 so that httptest servers on 127.0.0.1 are accepted.
func newTestDispatcher(cfgs []config.WebhookConfig) *WebhookDispatcher {
	prev := os.Getenv("DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST")
	os.Setenv("DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST", "1")
	d := NewWebhookDispatcher(cfgs)
	if prev == "" {
		os.Unsetenv("DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST")
	} else {
		os.Setenv("DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST", prev)
	}
	if d != nil {
		d.retryBackoff = 0
	}
	return d
}

// ---------------------------------------------------------------------------
// Full realistic E2E test: multi-event enforcement pipeline
// ---------------------------------------------------------------------------

func TestWebhookE2E_FullEnforcementPipeline(t *testing.T) {
	slackReceiver := newCollector()
	defer slackReceiver.Close()

	pagerdutyReceiver := newCollector()
	defer pagerdutyReceiver.Close()
	pagerdutyReceiver.statusFn = func(int) int { return 202 }

	genericReceiver := newCollector()
	defer genericReceiver.Close()

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
			MinSeverity:    "INFO",
			Events:         []string{"block", "drift", "guardrail", "scan"},
			TimeoutSeconds: 5,
			Enabled:        true,
		},
	})
	if d == nil {
		t.Fatal("expected non-nil dispatcher")
	}

	skillBlockEvent := audit.Event{
		ID: "evt-watcher-001", Timestamp: time.Now().UTC(),
		Action: "block", Target: "crypto-miner-skill", Actor: "defenseclaw-watcher",
		Details: "type=skill severity=CRITICAL findings=7 actions=quarantined,blocked,disabled reason=malware signature detected",
		Severity: "CRITICAL", RunID: "run-e2e-pipeline",
	}
	d.Dispatch(skillBlockEvent)

	driftEvent := audit.Event{
		ID: "evt-drift-002", Timestamp: time.Now().UTC(),
		Action: "drift", Target: "/home/user/.openclaw/workspace/skills/data-analyzer",
		Actor: "defenseclaw-rescan", Severity: "HIGH",
		Details: `[{"type":"dependency_change","severity":"MEDIUM"}]`,
	}
	d.Dispatch(driftEvent)

	guardrailBlockEvent := audit.Event{
		ID: "evt-guardrail-003", Timestamp: time.Now().UTC(),
		Action: "guardrail-block", Target: "anthropic/claude-sonnet-4-20250514",
		Actor: "defenseclaw-guardrail", Severity: "HIGH",
		Details: "direction=prompt action=block severity=HIGH findings=2",
	}
	d.Dispatch(guardrailBlockEvent)

	scanEvent := audit.Event{
		ID: "evt-scan-004", Timestamp: time.Now().UTC(),
		Action: "scan", Target: "safe-utility-skill", Actor: "defenseclaw",
		Details: "scanner=skill-scanner findings=0 max_severity=INFO", Severity: "INFO",
	}
	d.Dispatch(scanEvent)

	d.Close()

	// Slack: MEDIUM threshold, events=[block,drift,guardrail] -> 3 payloads
	slackPayloads := slackReceiver.get()
	if len(slackPayloads) != 3 {
		t.Errorf("[slack] expected 3 payloads, got %d", len(slackPayloads))
	}
	for _, p := range slackPayloads {
		if p.ContentType != "application/json" {
			t.Errorf("[slack] expected Content-Type=application/json, got %q", p.ContentType)
		}
		attachments, ok := p.Body["attachments"].([]interface{})
		if !ok || len(attachments) == 0 {
			t.Error("[slack] missing attachments array")
		}
	}
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

	// PagerDuty: HIGH threshold, events=[block] -> 1 payload
	pdPayloads := pagerdutyReceiver.get()
	if len(pdPayloads) != 1 {
		t.Errorf("[pagerduty] expected 1 payload, got %d", len(pdPayloads))
	}
	if len(pdPayloads) >= 1 {
		body := pdPayloads[0].Body
		if body["event_action"] != "trigger" {
			t.Errorf("[pagerduty] expected event_action=trigger, got %v", body["event_action"])
		}
		payload := body["payload"].(map[string]interface{})
		if payload["severity"] != "critical" {
			t.Errorf("[pagerduty] expected severity=critical, got %v", payload["severity"])
		}
		cd := payload["custom_details"].(map[string]interface{})
		if cd["event_id"] != "evt-watcher-001" {
			t.Errorf("[pagerduty] event_id should be evt-watcher-001, got %v", cd["event_id"])
		}
	}

	// Generic: INFO threshold, events=[block,drift,guardrail,scan] -> 4 payloads
	genPayloads := genericReceiver.get()
	if len(genPayloads) != 4 {
		t.Errorf("[generic] expected 4 payloads, got %d", len(genPayloads))
	}
	byID := make(map[string]receivedPayload)
	for _, p := range genPayloads {
		evt := p.Body["event"].(map[string]interface{})
		id, _ := evt["id"].(string)
		byID[id] = p
	}
	if _, ok := byID["evt-watcher-001"]; !ok {
		t.Error("[generic] missing evt-watcher-001")
	}
	if _, ok := byID["evt-drift-002"]; !ok {
		t.Error("[generic] missing evt-drift-002")
	}
	if _, ok := byID["evt-guardrail-003"]; !ok {
		t.Error("[generic] missing evt-guardrail-003")
	}
	if _, ok := byID["evt-scan-004"]; !ok {
		t.Error("[generic] missing evt-scan-004")
	}
}

// ---------------------------------------------------------------------------
// Retry under transient failures
// ---------------------------------------------------------------------------

func TestWebhookE2E_RetryOnTransientFailure(t *testing.T) {
	receiver := newCollector()
	defer receiver.Close()
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
}

func TestWebhookE2E_AllRetriesExhausted(t *testing.T) {
	receiver := newCollector()
	defer receiver.Close()
	receiver.statusFn = func(int) int { return 500 }

	d := newTestDispatcher([]config.WebhookConfig{
		{URL: receiver.URL(), Type: "generic", MinSeverity: "INFO", Enabled: true},
	})

	d.Dispatch(testEvent())
	d.Close()

	got := receiver.count()
	expected := webhookMaxRetries + 1
	if got != expected {
		t.Errorf("expected %d total attempts, got %d", expected, got)
	}
}

// ---------------------------------------------------------------------------
// 4xx permanent failures (not retried)
// ---------------------------------------------------------------------------

func TestWebhookE2E_4xxNotRetried(t *testing.T) {
	for _, code := range []int{400, 401, 403, 404} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			receiver := newCollector()
			defer receiver.Close()
			receiver.statusFn = func(int) int { return code }

			d := newTestDispatcher([]config.WebhookConfig{
				{URL: receiver.URL(), Type: "generic", MinSeverity: "INFO", Enabled: true},
			})
			d.Dispatch(testEvent())
			d.Close()

			if receiver.count() != 1 {
				t.Errorf("%d should be permanent (1 attempt), got %d", code, receiver.count())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// HMAC signing on generic endpoints (E2E)
// ---------------------------------------------------------------------------

func TestWebhookE2E_GenericHMACSignature(t *testing.T) {
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
	if !strings.HasPrefix(payloads[0].SigHdr, "sha256=") {
		t.Errorf("expected X-Hub-Signature-256 with sha256= prefix, got %q", payloads[0].SigHdr)
	}
}

func TestWebhookE2E_SlackNoSignatureHeader(t *testing.T) {
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
	if payloads[0].SigHdr != "" {
		t.Errorf("slack should not include signature header, got %q", payloads[0].SigHdr)
	}
}

// ---------------------------------------------------------------------------
// Webex integration
// ---------------------------------------------------------------------------

func TestWebhookE2E_WebexPayloadAndAuth(t *testing.T) {
	receiver := newCollector()
	defer receiver.Close()

	t.Setenv("WEBEX_BOT_TOKEN_E2E", "NjM0ZDk1OTEtYzRmOC00ZTJlLWI4YjgtOTIwMGQwNT")

	d := newTestDispatcher([]config.WebhookConfig{
		{
			URL: receiver.URL(), Type: "webex",
			SecretEnv: "WEBEX_BOT_TOKEN_E2E",
			RoomID:    "Y2lzY29zcGFyazovL3VzL1JPT00vc2VjdXJpdHktYWxlcnRz",
			Enabled:   true,
		},
	})

	d.Dispatch(audit.Event{
		ID: "evt-webex-001", Timestamp: time.Now().UTC(),
		Action: "block", Target: "crypto-miner-skill", Actor: "defenseclaw-watcher",
		Severity: "CRITICAL",
	})
	d.Close()

	payloads := receiver.get()
	if len(payloads) != 1 {
		t.Fatalf("expected 1 Webex payload, got %d", len(payloads))
	}
	p := payloads[0]
	if p.AuthHdr != "Bearer NjM0ZDk1OTEtYzRmOC00ZTJlLWI4YjgtOTIwMGQwNT" {
		t.Errorf("expected Bearer token, got %q", p.AuthHdr)
	}
	if p.SigHdr != "" {
		t.Errorf("Webex should not set X-Hub-Signature-256, got %q", p.SigHdr)
	}
	if p.Body["roomId"] != "Y2lzY29zcGFyazovL3VzL1JPT00vc2VjdXJpdHktYWxlcnRz" {
		t.Errorf("expected roomId to match, got %v", p.Body["roomId"])
	}
	md, _ := p.Body["markdown"].(string)
	if !strings.Contains(md, "evt-webex-001") {
		t.Errorf("markdown should contain event ID, got %q", md)
	}
}

func TestWebhookE2E_WebexInPipeline(t *testing.T) {
	slackReceiver := newCollector()
	defer slackReceiver.Close()
	webexReceiver := newCollector()
	defer webexReceiver.Close()
	genericReceiver := newCollector()
	defer genericReceiver.Close()

	t.Setenv("WEBEX_BOT_TOKEN_PIPE", "testtoken123")

	d := newTestDispatcher([]config.WebhookConfig{
		{URL: slackReceiver.URL(), Type: "slack", MinSeverity: "HIGH", Events: []string{"block"}, Enabled: true},
		{URL: webexReceiver.URL(), Type: "webex", SecretEnv: "WEBEX_BOT_TOKEN_PIPE", RoomID: "room-123", MinSeverity: "MEDIUM", Events: []string{"block", "drift"}, Enabled: true},
		{URL: genericReceiver.URL(), Type: "generic", MinSeverity: "INFO", Enabled: true},
	})

	d.Dispatch(audit.Event{
		ID: "evt-pipe-001", Timestamp: time.Now().UTC(),
		Action: "block", Target: "evil-skill", Actor: "watcher", Severity: "CRITICAL",
	})
	d.Dispatch(audit.Event{
		ID: "evt-pipe-002", Timestamp: time.Now().UTC(),
		Action: "drift", Target: "mutated-skill", Actor: "rescan", Severity: "MEDIUM",
	})
	d.Close()

	if slackReceiver.count() != 1 {
		t.Errorf("[slack] expected 1, got %d", slackReceiver.count())
	}
	if webexReceiver.count() != 2 {
		t.Errorf("[webex] expected 2, got %d", webexReceiver.count())
	}
	if genericReceiver.count() != 2 {
		t.Errorf("[generic] expected 2, got %d", genericReceiver.count())
	}
	for _, p := range webexReceiver.get() {
		if p.AuthHdr != "Bearer testtoken123" {
			t.Errorf("[webex] expected Bearer auth, got %q", p.AuthHdr)
		}
	}
}

// ---------------------------------------------------------------------------
// Severity edge cases
// ---------------------------------------------------------------------------

func TestWebhookE2E_SeverityEdgeCases(t *testing.T) {
	severities := []string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

	for _, threshold := range severities {
		for _, eventSev := range severities {
			t.Run(threshold+"_accepts_"+eventSev, func(t *testing.T) {
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
				expected := audit.SeverityRank(eventSev) >= audit.SeverityRank(threshold)
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
		t.Errorf("active should receive 1, got %d", activeReceiver.count())
	}
	if disabledReceiver.count() != 0 {
		t.Errorf("disabled should receive 0, got %d", disabledReceiver.count())
	}
}

// ---------------------------------------------------------------------------
// Concurrent dispatch safety
// ---------------------------------------------------------------------------

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
				ID: time.Now().Format("20060102150405.000000") + "-" + string(rune('A'+i%26)),
				Timestamp: time.Now().UTC(),
				Action: "block", Target: "concurrent-skill", Actor: "test", Severity: "HIGH",
			}
			d.Dispatch(evt)
		}(i)
	}
	wg.Wait()
	d.Close()

	if receiver.count() != numEvents {
		t.Errorf("expected %d, got %d", numEvents, receiver.count())
	}
}

// ---------------------------------------------------------------------------
// Post-close dispatch
// ---------------------------------------------------------------------------

func TestWebhookE2E_DispatchAfterClose(t *testing.T) {
	receiver := newCollector()
	defer receiver.Close()

	d := newTestDispatcher([]config.WebhookConfig{
		{URL: receiver.URL(), Type: "generic", Enabled: true},
	})

	d.Dispatch(testEvent())
	d.Close()

	before := receiver.count()
	d.Dispatch(testEvent())
	d.Dispatch(testEvent())
	time.Sleep(50 * time.Millisecond)

	if receiver.count() != before {
		t.Errorf("expected no new payloads after Close, before=%d after=%d", before, receiver.count())
	}
}
