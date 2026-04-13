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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// WebhookDispatcher sends structured JSON payloads to configured webhook
// endpoints when enforcement events occur. Modeled after the SplunkForwarder.
type WebhookDispatcher struct {
	endpoints    []webhookEndpoint
	client       *http.Client
	retryBackoff time.Duration
	wg           sync.WaitGroup
	done         chan struct{}
}

type webhookEndpoint struct {
	url         string
	channelType string // slack, pagerduty, webex, generic
	secret      string
	roomID      string
	minSeverity int
	events      map[string]bool
}

const (
	webhookMaxRetries   = 3
	webhookRetryBackoff = 2 * time.Second
)

// NewWebhookDispatcher creates a dispatcher from the config slice.
// Endpoints with enabled=false or empty URL are skipped.
func NewWebhookDispatcher(cfgs []config.WebhookConfig) *WebhookDispatcher {
	var endpoints []webhookEndpoint
	for _, c := range cfgs {
		if !c.Enabled || c.URL == "" {
			continue
		}
		evts := make(map[string]bool)
		for _, e := range c.Events {
			evts[strings.ToLower(e)] = true
		}
		timeout := time.Duration(c.TimeoutSeconds) * time.Second
		if timeout <= 0 {
			timeout = 10 * time.Second
		}
		endpoints = append(endpoints, webhookEndpoint{
			url:         c.URL,
			channelType: strings.ToLower(c.Type),
			secret:      c.ResolvedSecret(),
			roomID:      c.RoomID,
			minSeverity: severityToRank(c.MinSeverity),
			events:      evts,
		})
		_ = timeout // per-endpoint timeout not used for shared client
	}
	if len(endpoints) == 0 {
		return nil
	}
	return &WebhookDispatcher{
		endpoints: endpoints,
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
		retryBackoff: webhookRetryBackoff,
		done:         make(chan struct{}),
	}
}

// Dispatch sends the event to all matching endpoints asynchronously.
// Events dispatched after Close are silently dropped.
func (d *WebhookDispatcher) Dispatch(event audit.Event) {
	if d == nil || d.closing() {
		return
	}
	rank := severityToRank(event.Severity)
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
		d.wg.Add(1)
		go func(ep *webhookEndpoint) {
			defer d.wg.Done()
			d.send(ep, event)
		}(ep)
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

func (d *WebhookDispatcher) send(ep *webhookEndpoint, event audit.Event) {
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
		fmt.Fprintf(os.Stderr, "[webhook] format error for %s: %v\n", ep.url, err)
		return
	}

	for attempt := 0; attempt <= webhookMaxRetries; attempt++ {
		if attempt > 0 {
			backoff := d.retryBackoff * time.Duration(attempt)
			time.Sleep(backoff)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, ep.url, bytes.NewReader(payload))
		if reqErr != nil {
			cancel()
			fmt.Fprintf(os.Stderr, "[webhook] request error for %s: %v\n", ep.url, reqErr)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		switch {
		case ep.channelType == "webex" && ep.secret != "":
			req.Header.Set("Authorization", "Bearer "+ep.secret)
		case ep.channelType == "generic" && ep.secret != "":
			req.Header.Set("X-Webhook-Secret", ep.secret)
		}

		resp, doErr := d.client.Do(req)
		cancel()
		if doErr != nil {
			fmt.Fprintf(os.Stderr, "[webhook] send to %s attempt %d/%d failed: %v\n",
				ep.url, attempt+1, webhookMaxRetries+1, doErr)
			continue
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			fmt.Fprintf(os.Stderr, "[webhook] sent to %s (status=%d action=%s severity=%s)\n",
				ep.url, resp.StatusCode, event.Action, event.Severity)
			return
		}
		fmt.Fprintf(os.Stderr, "[webhook] %s returned %d, attempt %d/%d\n",
			ep.url, resp.StatusCode, attempt+1, webhookMaxRetries+1)
	}
	fmt.Fprintf(os.Stderr, "[webhook] exhausted retries for %s\n", ep.url)
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
		"roomId":   roomID,
		"markdown": markdown,
	}
	return json.Marshal(payload)
}

func formatGenericPayload(event audit.Event) ([]byte, error) {
	payload := map[string]interface{}{
		"webhook_type":        "defenseclaw_enforcement",
		"defenseclaw_version": "1.0",
		"event": map[string]interface{}{
			"id":        event.ID,
			"timestamp": event.Timestamp.Format(time.RFC3339),
			"action":    event.Action,
			"target":    event.Target,
			"actor":     event.Actor,
			"details":   event.Details,
			"severity":  event.Severity,
			"run_id":    event.RunID,
			"trace_id":  event.TraceID,
		},
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

func severityToRank(s string) int {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	case "INFO":
		return 1
	default:
		return 0
	}
}

func categorizeAction(action string) string {
	switch {
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
