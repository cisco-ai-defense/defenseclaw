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
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/google/uuid"
)

// WebhookDispatcher sends structured JSON payloads to configured webhook
// endpoints when enforcement events occur. Modeled after the SplunkForwarder.
type WebhookDispatcher struct {
	endpoints    []webhookEndpoint
	client       *http.Client
	retryBackoff time.Duration
	sem          chan struct{} // bounded concurrency
	logger       *log.Logger
	debug        bool
	wg           sync.WaitGroup
	done         chan struct{}
}

type webhookEndpoint struct {
	url         string
	channelType string // slack, pagerduty, webex, generic
	secret      string
	roomID      string
	timeout     time.Duration
	minSeverity int
	events      map[string]bool
	cooldown    time.Duration
	mu          sync.Mutex
	lastSent    map[string]time.Time // key: "target\x00action"
}

const (
	webhookMaxRetries      = 3
	webhookRetryBackoff    = 2 * time.Second
	webhookMaxConcurrency  = 20
	webhookDefaultTimeout  = 10 * time.Second
	webhookDefaultCooldown = 300 * time.Second // 5 minutes
)

// NewWebhookDispatcher creates a dispatcher from the config slice.
// Endpoints with enabled=false, empty URL, or unsafe URLs are skipped.
func NewWebhookDispatcher(cfgs []config.WebhookConfig) *WebhookDispatcher {
	logger := log.New(os.Stderr, "[webhook] ", 0)
	var endpoints []webhookEndpoint
	for _, c := range cfgs {
		if !c.Enabled || c.URL == "" {
			continue
		}
		if err := validateWebhookURL(c.URL); err != nil {
			logger.Printf("rejected endpoint %s: %v", c.URL, err)
			continue
		}
		evts := make(map[string]bool)
		for _, e := range c.Events {
			evts[strings.ToLower(e)] = true
		}
		timeout := time.Duration(c.TimeoutSeconds) * time.Second
		if timeout <= 0 {
			timeout = webhookDefaultTimeout
		}
		var cooldown time.Duration
		switch {
		case c.CooldownSeconds == nil:
			cooldown = webhookDefaultCooldown
		case *c.CooldownSeconds <= 0:
			cooldown = 0
		default:
			cooldown = time.Duration(*c.CooldownSeconds) * time.Second
		}
		endpoints = append(endpoints, webhookEndpoint{
			url:         c.URL,
			channelType: strings.ToLower(c.Type),
			secret:      c.ResolvedSecret(),
			roomID:      c.RoomID,
			minSeverity: audit.SeverityRank(c.MinSeverity),
			events:      evts,
			timeout:     timeout,
			cooldown:    cooldown,
			lastSent:    make(map[string]time.Time),
		})
	}
	if len(endpoints) == 0 {
		return nil
	}
	return &WebhookDispatcher{
		endpoints: endpoints,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		retryBackoff: webhookRetryBackoff,
		sem:          make(chan struct{}, webhookMaxConcurrency),
		logger:       logger,
		debug:        os.Getenv("DEFENSECLAW_WEBHOOK_DEBUG") == "1",
		done:         make(chan struct{}),
	}
}

// Dispatch sends the event to all matching endpoints asynchronously.
// Events dispatched after Close are silently dropped.
//
// The Details field is redacted here as a last-mile belt-and-braces
// guarantee: while audit.Logger.forwardToSinks already redacts,
// several callers (proxy.sendEnforcementAlert, sidecar health alerts,
// watchdog recovery alerts) build events directly and call Dispatch
// without going through audit.Logger. Redacting at the webhook
// boundary makes the PII-safety property hold regardless of the
// caller's discipline. ForSinkReason is idempotent so the double-
// redaction case is a no-op.
func (d *WebhookDispatcher) Dispatch(event audit.Event) {
	if d == nil || d.closing() {
		return
	}
	event.Details = redaction.ForSinkReason(event.Details)
	if event.ID == "" {
		event.ID = uuid.New().String()
	}
	rank := audit.SeverityRank(event.Severity)
	action := strings.ToLower(event.Action)
	eventCategory := categorizeAction(action)

	for i := range d.endpoints {
		ep := &d.endpoints[i]
		if rank < ep.minSeverity {
			continue
		}
		if len(ep.events) > 0 && !ep.events[eventCategory] {
			continue
		}
		cooldownKey := event.Target + "\x00" + action
		if !ep.claimSlot(cooldownKey) {
			d.logger.Printf("suppressed duplicate %s/%s for %s (cooldown %s)",
				event.Target, action, ep.url, ep.cooldown)
			continue
		}
		d.wg.Add(1)
		go func(ep *webhookEndpoint, key string) {
			defer d.wg.Done()
			d.sem <- struct{}{}
			defer func() { <-d.sem }()
			if d.send(ep, event) {
				ep.confirmSent(key)
			} else {
				ep.releaseSlot(key)
			}
		}(ep, cooldownKey)
	}
}

// Close drains all in-flight sends (including retries) and then returns.
// New dispatches after Close are silently dropped.
func (d *WebhookDispatcher) Close() {
	if d == nil {
		return
	}
	select {
	case <-d.done:
	default:
		close(d.done)
	}
	d.wg.Wait()
}

// closing returns true after Close has been called.
func (d *WebhookDispatcher) closing() bool {
	select {
	case <-d.done:
		return true
	default:
		return false
	}
}

// claimSlot atomically checks the cooldown and reserves the slot so
// concurrent dispatches for the same key are suppressed. Returns false
// if the key is already within its cooldown window.
func (ep *webhookEndpoint) claimSlot(key string) bool {
	if ep.cooldown <= 0 {
		return true
	}
	ep.mu.Lock()
	defer ep.mu.Unlock()
	if last, ok := ep.lastSent[key]; ok && time.Since(last) < ep.cooldown {
		return false
	}
	ep.lastSent[key] = time.Now()
	return true
}

// confirmSent refreshes the cooldown timestamp to the actual delivery
// time and lazily prunes stale entries.
func (ep *webhookEndpoint) confirmSent(key string) {
	if ep.cooldown <= 0 {
		return
	}
	now := time.Now()
	ep.mu.Lock()
	defer ep.mu.Unlock()
	ep.lastSent[key] = now
	if len(ep.lastSent) > 64 {
		pruneThreshold := 2 * ep.cooldown
		for k, ts := range ep.lastSent {
			if now.Sub(ts) > pruneThreshold {
				delete(ep.lastSent, k)
			}
		}
	}
}

// releaseSlot removes the cooldown claim when delivery fails, allowing
// future dispatch attempts for the same key.
func (ep *webhookEndpoint) releaseSlot(key string) {
	if ep.cooldown <= 0 {
		return
	}
	ep.mu.Lock()
	defer ep.mu.Unlock()
	delete(ep.lastSent, key)
}

func (d *WebhookDispatcher) send(ep *webhookEndpoint, event audit.Event) bool {
	var payload []byte
	var err error

	switch ep.channelType {
	case "slack":
		payload, err = formatSlackPayload(event)
	case "pagerduty":
		payload, err = formatPagerDutyPayload(event, ep.secret)
	case "webex":
		payload, err = formatWebexPayload(event, ep.roomID)
	default:
		payload, err = formatGenericPayload(event)
	}
	if err != nil {
		d.logger.Printf("format error for %s: %v", ep.url, err)
		return false
	}

	for attempt := 0; attempt <= webhookMaxRetries; attempt++ {
		if attempt > 0 {
			backoff := d.retryBackoff * time.Duration(attempt)
			time.Sleep(backoff)
		}

		ctx, cancel := context.WithTimeout(context.Background(), ep.timeout)
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, ep.url, bytes.NewReader(payload))
		if reqErr != nil {
			cancel()
			d.logger.Printf("request error for %s: %v", ep.url, reqErr)
			return false
		}
		req.Header.Set("Content-Type", "application/json")
		d.setAuthHeaders(req, ep, payload)

		resp, doErr := d.client.Do(req)
		cancel()
		if doErr != nil {
			d.logger.Printf("send to %s attempt %d/%d failed: %v",
				ep.url, attempt+1, webhookMaxRetries+1, doErr)
			continue
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if d.debug {
				d.logger.Printf("sent to %s (status=%d action=%s severity=%s)",
					ep.url, resp.StatusCode, event.Action, event.Severity)
			}
			return true
		}

		if !isRetryable(resp.StatusCode) {
			d.logger.Printf("%s returned %d (permanent failure), not retrying",
				ep.url, resp.StatusCode)
			return false
		}

		if resp.StatusCode == 429 {
			if ra := resp.Header.Get("Retry-After"); ra != "" {
				if secs, parseErr := strconv.Atoi(ra); parseErr == nil && secs > 0 && secs <= 120 {
					time.Sleep(time.Duration(secs) * time.Second)
					continue
				}
			}
		}

		d.logger.Printf("%s returned %d, attempt %d/%d",
			ep.url, resp.StatusCode, attempt+1, webhookMaxRetries+1)
	}
	d.logger.Printf("exhausted retries for %s", ep.url)
	return false
}

// setAuthHeaders applies authentication and payload signing per channel type.
func (d *WebhookDispatcher) setAuthHeaders(req *http.Request, ep *webhookEndpoint, payload []byte) {
	if ep.secret == "" {
		return
	}
	switch ep.channelType {
	case "webex":
		req.Header.Set("Authorization", "Bearer "+ep.secret)
	case "generic":
		sig := computeHMAC(payload, ep.secret)
		req.Header.Set("X-Hub-Signature-256", "sha256="+sig)
	case "pagerduty":
		// routing_key is in the payload body, no header needed
	}
}

// computeHMAC returns the hex-encoded HMAC-SHA256 of data using the given key.
func computeHMAC(data []byte, key string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

// isRetryable returns true for status codes that may succeed on retry.
func isRetryable(status int) bool {
	return status == 429 || (status >= 500 && status < 600)
}

// ---------------------------------------------------------------------------
// URL validation (SSRF prevention)
// ---------------------------------------------------------------------------

// validateWebhookURL ensures the URL is safe for outbound webhook delivery.
// Blocks non-HTTP schemes, localhost, private/link-local IP ranges, and
// cloud metadata endpoints.
func validateWebhookURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return fmt.Errorf("scheme %q not allowed (must be http or https)", scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("empty hostname")
	}
	allowLocal := os.Getenv("DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST") == "1"

	hostLower := strings.ToLower(host)
	if hostLower == "localhost" {
		if !allowLocal {
			return fmt.Errorf("localhost not allowed (set DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST=1 for local dev)")
		}
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		ips, resolveErr := net.LookupIP(host)
		if resolveErr != nil {
			return nil // allow DNS names that can't be resolved at config time
		}
		for _, resolved := range ips {
			if isPrivateIP(resolved) {
				if allowLocal && resolved.IsLoopback() {
					continue
				}
				return fmt.Errorf("hostname %q resolves to private IP %s", host, resolved)
			}
		}
		return nil
	}
	if isPrivateIP(ip) {
		if allowLocal && ip.IsLoopback() {
			return nil
		}
		return fmt.Errorf("IP %s is private/reserved", ip)
	}
	return nil
}

func isPrivateIP(ip net.IP) bool {
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16", // link-local / cloud metadata
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}
	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Payload formatters
// ---------------------------------------------------------------------------

func formatSlackPayload(event audit.Event) ([]byte, error) {
	color := slackColor(event.Severity)
	title := fmt.Sprintf("DefenseClaw: %s", event.Action)
	fields := []map[string]interface{}{
		{"type": "mrkdwn", "text": fmt.Sprintf("*Severity:* %s", event.Severity)},
		{"type": "mrkdwn", "text": fmt.Sprintf("*Target:* %s", event.Target)},
	}
	if event.Details != "" {
		details := event.Details
		if len(details) > 500 {
			details = details[:500] + "..."
		}
		fields = append(fields, map[string]interface{}{
			"type": "mrkdwn", "text": fmt.Sprintf("*Details:* %s", details),
		})
	}

	payload := map[string]interface{}{
		"attachments": []map[string]interface{}{
			{
				"color": color,
				"blocks": []map[string]interface{}{
					{
						"type": "header",
						"text": map[string]string{"type": "plain_text", "text": title},
					},
					{
						"type":   "section",
						"fields": fields,
					},
					{
						"type": "context",
						"elements": []map[string]string{
							{"type": "mrkdwn", "text": fmt.Sprintf("_Event ID: %s | %s_", event.ID, event.Timestamp.Format(time.RFC3339))},
						},
					},
				},
			},
		},
	}
	return json.Marshal(payload)
}

func formatPagerDutyPayload(event audit.Event, routingKey string) ([]byte, error) {
	pdSeverity := "info"
	switch strings.ToUpper(event.Severity) {
	case "CRITICAL":
		pdSeverity = "critical"
	case "HIGH":
		pdSeverity = "error"
	case "MEDIUM":
		pdSeverity = "warning"
	}

	payload := map[string]interface{}{
		"routing_key":  routingKey,
		"event_action": "trigger",
		"dedup_key":    fmt.Sprintf("defenseclaw-%s-%s", event.Target, event.Action),
		"payload": map[string]interface{}{
			"summary":   fmt.Sprintf("DefenseClaw %s: %s on %s", event.Action, event.Severity, event.Target),
			"source":    "defenseclaw",
			"severity":  pdSeverity,
			"timestamp": event.Timestamp.Format(time.RFC3339),
			"custom_details": map[string]string{
				"action":   event.Action,
				"target":   event.Target,
				"severity": event.Severity,
				"details":  event.Details,
				"event_id": event.ID,
			},
		},
	}
	return json.Marshal(payload)
}

func formatWebexPayload(event audit.Event, roomID string) ([]byte, error) {
	severity := strings.ToUpper(event.Severity)
	icon := webexSeverityIcon(severity)
	markdown := fmt.Sprintf(
		"%s **DefenseClaw: %s**\n\n"+
			"- **Severity:** %s\n"+
			"- **Target:** `%s`\n"+
			"- **Actor:** %s\n",
		icon, event.Action, severity, event.Target, event.Actor,
	)
	if event.Details != "" {
		details := event.Details
		if len(details) > 500 {
			details = details[:500] + "..."
		}
		markdown += fmt.Sprintf("- **Details:** %s\n", details)
	}
	markdown += fmt.Sprintf("\n_Event ID: %s | %s_", event.ID, event.Timestamp.Format(time.RFC3339))

	payload := map[string]interface{}{
		"markdown": markdown,
	}
	if roomID != "" {
		payload["roomId"] = roomID
	}
	return json.Marshal(payload)
}

func formatGenericPayload(event audit.Event) ([]byte, error) {
	eventData := map[string]interface{}{
		"id":        event.ID,
		"timestamp": event.Timestamp.Format(time.RFC3339),
		"action":    event.Action,
		"target":    event.Target,
		"actor":     event.Actor,
		"details":   event.Details,
		"severity":  event.Severity,
		"run_id":    event.RunID,
		"trace_id":  event.TraceID,
	}
	if strings.Contains(strings.ToLower(event.Action), "block") {
		eventData["defenseclaw_blocked"] = true
		eventData["defenseclaw_reason"] = event.Details
	}
	payload := map[string]interface{}{
		"webhook_type":        "defenseclaw_enforcement",
		"defenseclaw_version": "1.0",
		"event":               eventData,
	}
	return json.Marshal(payload)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func slackColor(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return "#FF0000"
	case "HIGH":
		return "#FF6600"
	case "MEDIUM":
		return "#FFCC00"
	case "LOW":
		return "#36A64F"
	default:
		return "#439FE0"
	}
}

func webexSeverityIcon(severity string) string {
	switch severity {
	case "CRITICAL":
		return "🔴"
	case "HIGH":
		return "🟠"
	case "MEDIUM":
		return "🟡"
	case "LOW":
		return "🟢"
	default:
		return "🔵"
	}
}

func categorizeAction(action string) string {
	switch {
	case strings.Contains(action, "gateway-down"),
		strings.Contains(action, "gateway-recovered"),
		strings.Contains(action, "guardrail-degraded"):
		return "health"
	case strings.Contains(action, "guardrail"):
		return "guardrail"
	case strings.Contains(action, "drift"),
		strings.Contains(action, "rescan"):
		return "drift"
	case strings.Contains(action, "block"),
		strings.Contains(action, "quarantine"),
		strings.Contains(action, "disable"):
		return "block"
	case strings.Contains(action, "scan"):
		return "scan"
	default:
		return action
	}
}
