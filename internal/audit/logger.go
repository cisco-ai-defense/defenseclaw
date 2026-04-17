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
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"

	"github.com/defenseclaw/defenseclaw/internal/audit/sinks"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

// sanitizeEvent rewrites free-form, PII-bearing fields on a copy of the
// supplied event so the version that reaches SQLite, audit sinks, and
// OTel exporters never carries raw user content.
//
// Intentionally applied once at the Logger choke point rather than at
// every call site: a single invariant ("persistent sinks get
// redacted events") is easier to audit and impossible to bypass by
// forgetting a helper. The Reveal flag is not honored here — persistent
// storage must never unmask.
//
// Target (the resource identifier) is preserved because it is usually
// a stable, non-PII id (skill name, model name, package coordinates).
// If a caller puts PII there (a user email as the actor, say) it
// flows through unchanged; the action/details/reason surfaces are
// where free-form user content historically leaks.
func sanitizeEvent(e Event) Event {
	e.Details = redaction.ForSinkReason(e.Details)
	return e
}

// StructuredEmitter receives every audit Event that flows through the
// Logger *after* it has been sanitized and persisted. It is intended for
// translating audit events into the structured gateway.jsonl envelope
// (see internal/gatewaylog) so non-gateway lifecycle signals (scans,
// watcher start/stop, enforcement actions) land alongside guardrail
// verdicts in a single correlated stream.
//
// Implementations must be safe for concurrent use and non-blocking; the
// Logger invokes Emit on the hot path and will not retry on failure.
type StructuredEmitter interface {
	EmitAudit(event Event)
}

type Logger struct {
	store *Store
	// sinks is the v4 generic fan-out manager. nil is a safe no-op
	// (matches the legacy nil-splunk behavior).
	sinks      *sinks.Manager
	otel       *telemetry.Provider
	structured StructuredEmitter
}

func NewLogger(store *Store) *Logger {
	return &Logger{store: store}
}

// SetSinks installs the audit-sink fan-out manager. Pass nil to disable
// downstream forwarding (events still hit SQLite + OTel when those are
// configured).
func (l *Logger) SetSinks(m *sinks.Manager) {
	l.sinks = m
}

func (l *Logger) SetOTelProvider(p *telemetry.Provider) {
	l.otel = p
}

// SetStructuredEmitter installs a bridge that forwards sanitized audit
// Events to the structured gateway.jsonl writer (or any other
// structured sink). Pass nil to detach.
func (l *Logger) SetStructuredEmitter(e StructuredEmitter) {
	l.structured = e
}

// emitStructured fans the event out to the structured emitter. Kept
// separate from forwardToSinks because the gatewaylog bridge is
// intentionally local-only (file on disk + OTel/Splunk fanout happens
// at the writer level, not here) while sinks.Manager is for remote
// adapters with retry/batching semantics.
func (l *Logger) emitStructured(e Event) {
	if l.structured == nil {
		return
	}
	l.structured.EmitAudit(e)
}

// LogScan persists a scan result to SQLite, forwards to Splunk HEC,
// and emits OTel log/metric signals.
func (l *Logger) LogScan(result *scanner.ScanResult) error {
	return l.LogScanWithVerdict(result, "")
}

// LogScanWithVerdict persists a scan result with an explicit admission verdict.
func (l *Logger) LogScanWithVerdict(result *scanner.ScanResult, verdict string) error {
	scanID := uuid.New().String()
	raw, _ := result.JSON()

	if err := l.store.InsertScanResult(
		scanID, result.Scanner, result.Target, result.Timestamp,
		result.Duration.Milliseconds(), len(result.Findings),
		string(result.MaxSeverity()), string(raw),
	); err != nil {
		if l.otel != nil {
			l.otel.RecordAuditDBError(context.Background(), "insert_scan_result")
		}
		return err
	}

	for _, f := range result.Findings {
		tagsJSON, _ := json.Marshal(f.Tags)
		findingID := uuid.New().String()
		// Redact free-form finding text before it lands in SQLite.
		// Description frequently contains the matched literal
		// (e.g. "detected SSN 123-45-6789"); Location is a file
		// path that can include usernames; Remediation text is
		// sometimes templated with the offending value. Title is
		// authored from static rule metadata and is safe.
		safeDescription := redaction.ForSinkString(f.Description)
		safeLocation := redaction.ForSinkString(f.Location)
		safeRemediation := redaction.ForSinkString(f.Remediation)
		if err := l.store.InsertFinding(
			findingID, scanID, string(f.Severity), f.Title,
			safeDescription, safeLocation, safeRemediation, f.Scanner,
			string(tagsJSON),
		); err != nil {
			if l.otel != nil {
				l.otel.RecordAuditDBError(context.Background(), "insert_finding")
			}
			return err
		}
	}

	event := sanitizeEvent(Event{
		ID:        uuid.New().String(),
		Timestamp: time.Now().UTC(),
		Action:    "scan",
		Target:    result.Target,
		Actor:     "defenseclaw",
		Details: fmt.Sprintf("scanner=%s findings=%d max_severity=%s duration=%s",
			result.Scanner, len(result.Findings), result.MaxSeverity(), result.Duration),
		Severity: string(result.MaxSeverity()),
		RunID:    currentRunID(),
	})

	if err := l.store.LogEvent(event); err != nil {
		if l.otel != nil {
			l.otel.RecordAuditDBError(context.Background(), "insert_event")
		}
		return err
	}
	if l.otel != nil {
		l.otel.RecordAuditEvent(context.Background(), event.Action, event.Severity)
	}
	l.forwardToSinks(event)
	l.emitStructured(event)

	if l.otel != nil {
		targetType := inferTargetType(result.Scanner)
		l.otel.EmitScanResult(result, scanID, targetType, verdict)
	}

	return nil
}

// LogAction persists an action event and emits OTel lifecycle signals.
func (l *Logger) LogAction(action, target, details string) error {
	return l.LogActionWithTrace(action, target, details, "")
}

// LogActionWithTrace persists an action event with an OTel trace ID for
// cross-system correlation between Splunk O11y and Splunk local.
func (l *Logger) LogActionWithTrace(action, target, details, traceID string) error {
	return l.LogActionWithCorrelation(action, target, details, traceID, "")
}

// LogActionWithCorrelation persists an action event with both an OTel
// trace ID and a gateway request ID. This is the single code path all
// new call sites should use once Phase 5 threading is live; the older
// LogAction / LogActionWithTrace helpers delegate here with the
// request_id left empty.
//
// An empty requestID is legal (pre-proxy subsystems like the watcher
// have no HTTP correlation context); the SQLite column is nullable
// and downstream sinks strip the attribute when unset.
func (l *Logger) LogActionWithCorrelation(action, target, details, traceID, requestID string) error {
	event := sanitizeEvent(Event{
		ID:        uuid.New().String(),
		Timestamp: time.Now().UTC(),
		Action:    action,
		Target:    target,
		Actor:     "defenseclaw",
		Details:   details,
		Severity:  "INFO",
		RunID:     currentRunID(),
		TraceID:   traceID,
		RequestID: requestID,
	})
	if err := l.store.LogEvent(event); err != nil {
		if l.otel != nil {
			l.otel.RecordAuditDBError(context.Background(), "insert_event")
		}
		return err
	}
	if l.otel != nil {
		l.otel.RecordAuditEvent(context.Background(), event.Action, event.Severity)
	}
	l.forwardToSinks(event)
	l.emitStructured(event)

	if l.otel != nil {
		assetType := inferAssetTypeFromAction(action, details)
		l.otel.EmitLifecycleEvent(action, target, assetType, details, event.Severity, nil)
	}

	return nil
}

// LogActionWithEnforcement persists an action event with enforcement metadata
// for OTel lifecycle signals. The enforcement map may contain keys:
// "install", "file", "runtime", "source_path".
func (l *Logger) LogActionWithEnforcement(action, target, details string, enforcement map[string]string) error {
	event := sanitizeEvent(Event{
		ID:        uuid.New().String(),
		Timestamp: time.Now().UTC(),
		Action:    action,
		Target:    target,
		Actor:     "defenseclaw",
		Details:   details,
		Severity:  "INFO",
		RunID:     currentRunID(),
	})
	if err := l.store.LogEvent(event); err != nil {
		if l.otel != nil {
			l.otel.RecordAuditDBError(context.Background(), "insert_event")
		}
		return err
	}
	if l.otel != nil {
		l.otel.RecordAuditEvent(context.Background(), event.Action, event.Severity)
	}
	l.forwardToSinks(event)
	l.emitStructured(event)

	if l.otel != nil {
		assetType := inferAssetTypeFromAction(action, details)
		l.otel.EmitLifecycleEvent(action, target, assetType, details, event.Severity, enforcement)
	}

	return nil
}

// LogEvent persists a pre-built event through the full audit pipeline
// (SQLite + audit sinks + OTel). Use this when the caller needs to
// control severity or other fields that LogAction hardcodes.
func (l *Logger) LogEvent(event Event) error {
	if event.ID == "" {
		event.ID = uuid.New().String()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	if event.RunID == "" {
		event.RunID = currentRunID()
	}
	event = sanitizeEvent(event)
	if err := l.store.LogEvent(event); err != nil {
		if l.otel != nil {
			l.otel.RecordAuditDBError(context.Background(), "insert_event")
		}
		return err
	}
	if l.otel != nil {
		l.otel.RecordAuditEvent(context.Background(), event.Action, event.Severity)
	}
	l.forwardToSinks(event)
	l.emitStructured(event)
	return nil
}

// forwardToSinks fans the event out to every configured audit sink. The
// Manager handles per-sink filtering, immediate-flush actions, and
// per-sink error logging — we only translate from the audit Event type.
//
// We use a short context here because the sinks are best-effort
// downstream forwarders; a stalled remote endpoint must not block the
// hot path. Sinks that need longer-lived connections own their own
// background goroutines.
func (l *Logger) forwardToSinks(e Event) {
	if l.sinks == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = l.sinks.Forward(ctx, sinks.Event{
		ID:        e.ID,
		Timestamp: e.Timestamp,
		Action:    e.Action,
		Target:    e.Target,
		Actor:     e.Actor,
		Details:   e.Details,
		Severity:  e.Severity,
		RunID:     e.RunID,
		TraceID:   e.TraceID,
		RequestID: e.RequestID,
	})
}

// Close flushes and closes every audit sink. Safe to call when no sinks
// are configured.
func (l *Logger) Close() {
	if l.sinks != nil {
		if err := l.sinks.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: audit sinks close: %v\n", err)
		}
	}
}

func inferTargetType(scannerName string) string {
	switch scannerName {
	case "mcp-scanner", "mcp_scanner":
		return "mcp"
	case "skill-scanner", "skill_scanner":
		return "skill"
	case "codeguard", "aibom", "aibom-claw",
		"clawshield-vuln", "clawshield-secrets", "clawshield-pii",
		"clawshield-malware", "clawshield-injection":
		return "code"
	default:
		return "unknown"
	}
}

func inferAssetTypeFromAction(action, details string) string {
	switch {
	case contains(action, "mcp") || contains(details, "type=mcp"):
		return "mcp"
	case contains(action, "skill") || contains(details, "type=skill"):
		return "skill"
	default:
		return "skill"
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
