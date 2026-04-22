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
	"context"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

// truncateUTF8 truncates s to at most maxBytes without splitting a UTF-8 code point.
func truncateUTF8(s string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(s) <= maxBytes {
		return s
	}
	for maxBytes > 0 && !utf8.RuneStart(s[maxBytes]) {
		maxBytes--
	}
	return s[:maxBytes]
}

// NetworkEgressEvent describes a single outbound network call observed by the
// agent runtime. It captures the destination, request shape, and policy
// decision as first-class structured fields rather than embedding them inside
// tool-argument text blobs.
//
// This makes it possible to answer questions like:
//   - "Which sessions made calls to api.example.com?"
//   - "How many egress calls were blocked in the last hour?"
//   - "Did any agent call a non-allowlisted hostname?"
//
// without scraping free-text audit_events details columns.
type NetworkEgressEvent struct {
	// Timestamp is when the call was observed. Defaults to now if zero.
	Timestamp time.Time `json:"timestamp"`

	// SessionID correlates this event to a specific agent session.
	// Empty when the session is not known (e.g. pre-session bootstrap calls).
	SessionID string `json:"session_id,omitempty"`

	// Hostname is the destination host (no port). Required.
	Hostname string `json:"hostname"`

	// URL is the full destination URL, truncated to 512 chars. Optional.
	URL string `json:"url,omitempty"`

	// HTTPMethod is the HTTP verb (GET, POST, …). Optional.
	HTTPMethod string `json:"http_method,omitempty"`

	// Protocol is "http" or "https". Optional.
	Protocol string `json:"protocol,omitempty"`

	// PolicyOutcome is a human-readable summary of the policy decision,
	// e.g. "Allowed by pattern: *.example.com" or "Denied: not in allowlist".
	PolicyOutcome string `json:"policy_outcome"`

	// DecisionCode is a machine-readable outcome token, e.g.
	// "NETWORK_ALLOW_PATTERN", "NETWORK_DENY_DEFAULT". Optional.
	DecisionCode string `json:"decision_code,omitempty"`

	// Blocked is true when the call was actively prevented by policy.
	Blocked bool `json:"blocked"`

	// Severity is INFO for allowed calls and HIGH for blocked calls.
	// Defaults based on Blocked when empty.
	Severity string `json:"severity,omitempty"`

	// Details holds any additional context (e.g. the matching policy pattern).
	Details string `json:"details,omitempty"`
}

// Validate returns an error if required fields are missing or invalid.
func (e *NetworkEgressEvent) Validate() error {
	if strings.TrimSpace(e.Hostname) == "" {
		return fmt.Errorf("audit: network egress event: hostname is required")
	}
	if strings.TrimSpace(e.PolicyOutcome) == "" {
		return fmt.Errorf("audit: network egress event: policy_outcome is required")
	}
	return nil
}

// effectiveSeverity returns the resolved severity, defaulting to HIGH for
// blocked calls and INFO for allowed ones.
func (e *NetworkEgressEvent) effectiveSeverity() string {
	if e.Severity != "" {
		return e.Severity
	}
	if e.Blocked {
		return "HIGH"
	}
	return "INFO"
}

// toRow converts the event to the store's persisted shape.
func (e *NetworkEgressEvent) toRow() NetworkEgressRow {
	url := e.URL
	if len(url) > 512 {
		url = truncateUTF8(url, 512)
	}
	return NetworkEgressRow{
		Timestamp:     e.Timestamp,
		SessionID:     e.SessionID,
		Hostname:      e.Hostname,
		URL:           url,
		HTTPMethod:    e.HTTPMethod,
		Protocol:      e.Protocol,
		PolicyOutcome: e.PolicyOutcome,
		DecisionCode:  e.DecisionCode,
		Blocked:       e.Blocked,
		Severity:      e.effectiveSeverity(),
		Details:       e.Details,
	}
}

// LogNetworkEgress persists an outbound network call as a structured audit
// row. For blocked calls it additionally:
//   - writes a HIGH-severity entry to audit_events so the alert panel and
//     /alerts endpoint surface it without a separate query;
//   - forwards that alert to every configured audit sink;
//   - mirrors that alert into the structured audit bridge so gateway.jsonl
//     stays in sync with the SQLite/TUI alert surfaces;
//   - emits an OTel alert counter.
//
// OTel audit-event counters are recorded for every call (allowed or blocked).
func (l *Logger) LogNetworkEgress(ctx context.Context, e NetworkEgressEvent) error {
	if err := e.Validate(); err != nil {
		return err
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}

	// Snapshot the collaborator graph once at entry so a concurrent
	// SetOTelProvider / SetSinks during shutdown cannot tear the
	// interface reads below (L1 finding: writes to interface fields
	// are two-word stores and are not atomic on most architectures).
	sinksMgr, otel, structured := l.snapshot()

	row := e.toRow()
	if err := l.store.InsertNetworkEgressEvent(row); err != nil {
		if otel != nil {
			otel.RecordAuditDBError(ctx, "insert_network_egress")
		}
		return err
	}

	// Record OTel audit-event counter for every egress observation.
	if otel != nil {
		otel.RecordAuditEvent(ctx, "network-egress", e.effectiveSeverity(), telemetry.MetricEnvelope{
			DestinationApp: e.Hostname,
			Result:         map[bool]string{true: "blocked", false: "allowed"}[e.Blocked],
		})
	}

	if !e.Blocked {
		return nil
	}

	// Blocked call: raise an audit_events alert so the TUI and /alerts
	// endpoint surface it without requiring a separate egress query.
	alert := sanitizeEvent(Event{
		ID:        uuid.New().String(),
		Timestamp: e.Timestamp,
		Action:    "network-egress-blocked",
		Target:    e.Hostname,
		Actor:     "defenseclaw",
		Details: fmt.Sprintf("url=%s method=%s decision=%s outcome=%s",
			truncateStr(e.URL, 200), e.HTTPMethod, e.DecisionCode, e.PolicyOutcome),
		Severity: "HIGH",
		RunID:    currentRunID(),
	})
	if err := l.store.LogEvent(alert); err != nil {
		// Non-fatal: the primary egress row is already persisted.
		fmt.Fprintf(os.Stderr, "[audit] network egress: alert event write failed: %v\n", err)
	} else {
		// Mirror the same sink + structured-emitter contract used by the
		// main Logger paths so blocked egress alerts land in downstream
		// fan-out with stable IDs/correlation metadata.
		l.forwardToSinksSnapshot(sinksMgr, alert)
		l.emitStructuredSnapshot(structured, alert)
	}

	// Emit OTel alert counter.
	if otel != nil {
		otel.RecordAlert(ctx, "network-egress-blocked", "HIGH", "network-policy")
	}

	return nil
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return truncateUTF8(s, max)
}
