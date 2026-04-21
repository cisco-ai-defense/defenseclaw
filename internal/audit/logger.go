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
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/defenseclaw/defenseclaw/internal/audit/sinks"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
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
	// EmitGatewayEvent writes a fully-formed gatewaylog event (activity,
	// structured errors) to gateway.jsonl. Optional — no-op when nil
	// emitter or bridge stub.
	EmitGatewayEvent(ev gatewaylog.Event)
}

// Logger is the audit choke point: every caller routes through
// LogEvent / LogAction* / LogScan*, which persist to SQLite and then
// fan out to OTel, audit sinks, and the structured gateway.jsonl
// bridge. The downstream collaborators (sinks.Manager,
// telemetry.Provider, StructuredEmitter) are installed via setters
// so sidecar startup can wire everything up after NewLogger without
// refactoring call sites every time a new sink is added.
//
// mu guards those three collaborator fields. Before it existed, a
// goroutine calling LogEvent while the shutdown path called
// SetStructuredEmitter(nil) had a classic data race on an interface
// value — interface writes are two-word stores on most
// architectures and are not atomic. The lock is acquired only to
// snapshot the current collaborator pointers into local variables;
// the fan-out itself runs *without* the lock held so a slow sink
// cannot block an unrelated setter from swapping.
type Logger struct {
	store *Store

	mu sync.RWMutex
	// sinks is the v4 generic fan-out manager. nil is a safe no-op
	// (matches the legacy nil-splunk behavior).
	sinks      *sinks.Manager
	otel       *telemetry.Provider
	structured StructuredEmitter
	// gwWriter is optional: when set, scan completions emit EventScan /
	// EventScanFinding rows through the gateway JSONL choke point.
	gwWriter *gatewaylog.Writer
}

func NewLogger(store *Store) *Logger {
	return &Logger{store: store}
}

// SetSinks installs the audit-sink fan-out manager. Pass nil to disable
// downstream forwarding (events still hit SQLite + OTel when those are
// configured).
func (l *Logger) SetSinks(m *sinks.Manager) {
	l.mu.Lock()
	l.sinks = m
	l.mu.Unlock()
	if m != nil {
		m.SetDeliveryHook(l.sinkDeliveryHook)
		m.SetCircuitCallbacks(l.onCircuitTripActivity, l.onCircuitRecoverActivity)
	}
}

func (l *Logger) SetOTelProvider(p *telemetry.Provider) {
	l.mu.Lock()
	l.otel = p
	l.mu.Unlock()
}

// SetStructuredEmitter installs a bridge that forwards sanitized audit
// Events to the structured gateway.jsonl writer (or any other
// structured sink). Pass nil to detach.
func (l *Logger) SetStructuredEmitter(e StructuredEmitter) {
	l.mu.Lock()
	l.structured = e
	l.mu.Unlock()
}

// SetGatewayLogWriter installs the gateway JSONL writer used for v7
// EventScan / EventScanFinding emissions. Pass nil to disable.
func (l *Logger) SetGatewayLogWriter(w *gatewaylog.Writer) {
	l.mu.Lock()
	l.gwWriter = w
	l.mu.Unlock()
}

func (l *Logger) gatewayWriterSnapshot() *gatewaylog.Writer {
	l.mu.RLock()
	w := l.gwWriter
	l.mu.RUnlock()
	return w
}

// snapshot returns a consistent view of the collaborator pointers
// at a single instant. The caller uses these snapshots to drive the
// fan-out without holding the lock — so a misbehaving sink cannot
// stall setters, and a concurrent Set* swap does not tear an
// in-flight interface field read.
func (l *Logger) snapshot() (*sinks.Manager, *telemetry.Provider, StructuredEmitter) {
	l.mu.RLock()
	s, o, e := l.sinks, l.otel, l.structured
	l.mu.RUnlock()
	return s, o, e
}

// emitStructuredSnapshot fans the event out to an explicit snapshot
// of the structured emitter. Used by code paths that have already
// taken a single snapshot() for the whole fan-out so concurrent
// Set*/Close calls can't observe a torn interface field mid-pipe.
func (l *Logger) emitStructuredSnapshot(emitter StructuredEmitter, e Event) {
	if emitter == nil {
		return
	}
	emitter.EmitAudit(e)
}

func (l *Logger) emitGatewaySnapshot(emitter StructuredEmitter, ev gatewaylog.Event) {
	if emitter == nil {
		return
	}
	emitter.EmitGatewayEvent(ev)
}

// ScanCorrelation threads per-request correlation identifiers and
// agent identity down into the scan emission pipeline (EventScan,
// EventScanFinding, scan_results and scan_findings SQLite rows).
//
// All fields are optional; the empty value is legal at every call
// site (watcher admission happens pre-session, CLI scans have no
// request/session context). The audit package cannot import
// internal/gateway to pull these out of context itself — callers
// who have the values populate the struct and pass it in.
type ScanCorrelation struct {
	RunID     string
	RequestID string
	SessionID string
	TraceID   string

	AgentID         string
	AgentName       string
	AgentInstanceID string
}

// LogScan persists a scan result to SQLite, forwards to Splunk HEC,
// and emits OTel log/metric signals.
func (l *Logger) LogScan(result *scanner.ScanResult) error {
	return l.LogScanWithVerdict(result, "")
}

// LogScanWithVerdict persists a scan result with an explicit admission verdict.
func (l *Logger) LogScanWithVerdict(result *scanner.ScanResult, verdict string) error {
	return l.LogScanWithCorrelation(context.Background(), result, verdict, ScanCorrelation{})
}

// LogScanWithCorrelation is the v7 entry point for scan emission
// with explicit correlation + identity. Threads run_id / request_id
// / session_id / trace_id and the three-tier agent identity onto
// EventScan, EventScanFinding, the scan_results / scan_findings
// rows, and the matching audit.Event so every surface agrees.
//
// ctx is passed through to scanner.EmitScanResult for tracing
// attachments; correlation IDs are taken from the corr parameter
// (not the context) so there is a single typed contract.
func (l *Logger) LogScanWithCorrelation(
	ctx context.Context,
	result *scanner.ScanResult,
	verdict string,
	corr ScanCorrelation,
) error {
	sinksMgr, otel, structured := l.snapshot()

	if verdict != "" {
		result.Verdict = verdict
	}

	if ctx == nil {
		ctx = context.Background()
	}
	var tel scanner.ScanTelemetry
	if otel != nil {
		tel = otel
	}
	runID := corr.RunID
	if runID == "" {
		runID = currentRunID()
	}
	// v7 clean break: AgentInstanceID is per-session (empty when no
	// session context is known, e.g. watcher admission); the process
	// UUID goes on SidecarInstanceID only. Consumers must not group
	// sessions by sidecar identity — that was the v6 pitfall.
	agent := scanner.AgentIdentity{
		AgentID:           corr.AgentID,
		AgentName:         corr.AgentName,
		AgentInstanceID:   corr.AgentInstanceID,
		SidecarInstanceID: ProcessAgentInstanceID(),
		RunID:             runID,
		RequestID:         corr.RequestID,
		SessionID:         corr.SessionID,
		TraceID:           corr.TraceID,
	}
	scanID, err := scanner.EmitScanResult(ctx, l.gatewayWriterSnapshot(), l.store, tel, result, agent)
	if err != nil {
		if otel != nil {
			otel.RecordAuditDBError(ctx, "emit_scan_result")
		}
		return err
	}

	event := sanitizeEvent(Event{
		ID:        uuid.New().String(),
		Timestamp: time.Now().UTC(),
		Action:    "scan",
		Target:    result.Target,
		Actor:     "defenseclaw",
		Details: fmt.Sprintf("scanner=%s findings=%d max_severity=%s duration=%s",
			result.Scanner, len(result.Findings), result.MaxSeverity(), result.Duration),
		Severity:          string(result.MaxSeverity()),
		RunID:             runID,
		RequestID:         corr.RequestID,
		SessionID:         corr.SessionID,
		TraceID:           corr.TraceID,
		AgentID:           corr.AgentID,
		AgentName:         corr.AgentName,
		AgentInstanceID:   corr.AgentInstanceID,
		SidecarInstanceID: ProcessAgentInstanceID(),
	})

	if err := l.store.LogEvent(event); err != nil {
		if otel != nil {
			otel.RecordAuditDBError(context.Background(), "insert_event")
		}
		return err
	}
	if otel != nil {
		otel.RecordAuditEvent(context.Background(), event.Action, event.Severity)
	}
	l.forwardToSinksSnapshot(sinksMgr, event)
	l.emitStructuredSnapshot(structured, event)

	if otel != nil {
		targetType := inferTargetType(result.Scanner)
		otel.EmitScanResult(result, scanID, targetType, verdict)
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
	sinksMgr, otel, structured := l.snapshot()
	event := sanitizeEvent(Event{
		ID:                uuid.New().String(),
		Timestamp:         time.Now().UTC(),
		Action:            action,
		Target:            target,
		Actor:             "defenseclaw",
		Details:           details,
		Severity:          "INFO",
		RunID:             currentRunID(),
		TraceID:           traceID,
		RequestID:         requestID,
		SidecarInstanceID: ProcessAgentInstanceID(),
	})
	if err := l.store.LogEvent(event); err != nil {
		if otel != nil {
			otel.RecordAuditDBError(context.Background(), "insert_event")
		}
		return err
	}
	if otel != nil {
		otel.RecordAuditEvent(context.Background(), event.Action, event.Severity)
	}
	l.forwardToSinksSnapshot(sinksMgr, event)
	l.emitStructuredSnapshot(structured, event)

	if otel != nil {
		assetType := inferAssetTypeFromAction(action, details)
		otel.EmitLifecycleEvent(action, target, assetType, details, event.Severity, nil)
	}

	return nil
}

// LogActionWithEnforcement persists an action event with enforcement metadata
// for OTel lifecycle signals. The enforcement map may contain keys:
// "install", "file", "runtime", "source_path".
func (l *Logger) LogActionWithEnforcement(action, target, details string, enforcement map[string]string) error {
	sinksMgr, otel, structured := l.snapshot()
	event := sanitizeEvent(Event{
		ID:                uuid.New().String(),
		Timestamp:         time.Now().UTC(),
		Action:            action,
		Target:            target,
		Actor:             "defenseclaw",
		Details:           details,
		Severity:          "INFO",
		RunID:             currentRunID(),
		SidecarInstanceID: ProcessAgentInstanceID(),
	})
	if err := l.store.LogEvent(event); err != nil {
		if otel != nil {
			otel.RecordAuditDBError(context.Background(), "insert_event")
		}
		return err
	}
	if otel != nil {
		otel.RecordAuditEvent(context.Background(), event.Action, event.Severity)
	}
	l.forwardToSinksSnapshot(sinksMgr, event)
	l.emitStructuredSnapshot(structured, event)

	if otel != nil {
		assetType := inferAssetTypeFromAction(action, details)
		otel.EmitLifecycleEvent(action, target, assetType, details, event.Severity, enforcement)
	}

	return nil
}

// LogEvent persists a pre-built event through the full audit pipeline
// (SQLite + audit sinks + OTel). Use this when the caller needs to
// control severity or other fields that LogAction hardcodes.
func (l *Logger) LogEvent(event Event) error {
	sinksMgr, otel, structured := l.snapshot()
	if event.ID == "" {
		event.ID = uuid.New().String()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	if event.RunID == "" {
		event.RunID = currentRunID()
	}
	// v7 clean break: AgentInstanceID is per-SESSION. Callers that
	// carry a session context (the router, proxy session resolver)
	// stamp it explicitly. Absence is meaningful — "no session
	// anchor for this event" — and must round-trip as empty.
	// The process-scoped identifier lives on SidecarInstanceID;
	// we auto-fill that one so every row has a stable sidecar
	// identity without burdening callers.
	if event.SidecarInstanceID == "" {
		event.SidecarInstanceID = ProcessAgentInstanceID()
	}
	event = sanitizeEvent(event)
	if err := l.store.LogEvent(event); err != nil {
		if otel != nil {
			otel.RecordAuditDBError(context.Background(), "insert_event")
		}
		return err
	}
	if otel != nil {
		otel.RecordAuditEvent(context.Background(), event.Action, event.Severity)
	}
	l.forwardToSinksSnapshot(sinksMgr, event)
	l.emitStructuredSnapshot(structured, event)
	return nil
}

// forwardToSinksSnapshot fans the event out to the provided sink
// manager snapshot. Kept separate from the field reader so a single
// Log* call observes exactly one snapshot of the collaborator graph
// — a concurrent SetSinks/SetStructuredEmitter cannot tear
// mid-pipeline.
//
// We use a short context here because the sinks are best-effort
// downstream forwarders; a stalled remote endpoint must not block the
// hot path. Sinks that need longer-lived connections own their own
// background goroutines.
func (l *Logger) forwardToSinksSnapshot(mgr *sinks.Manager, e Event) {
	if mgr == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	l.forwardSinkEventCtx(ctx, mgr, sinks.Event{
		ID:                e.ID,
		Timestamp:         e.Timestamp,
		Action:            e.Action,
		Target:            e.Target,
		Actor:             e.Actor,
		Details:           e.Details,
		Severity:          e.Severity,
		RunID:             e.RunID,
		TraceID:           e.TraceID,
		RequestID:         e.RequestID,
		SessionID:         e.SessionID,
		AgentName:         e.AgentName,
		AgentID:           e.AgentID,
		AgentInstanceID:   e.AgentInstanceID,
		SidecarInstanceID: e.SidecarInstanceID,
		PolicyID:          e.PolicyID,
		DestinationApp:    e.DestinationApp,
		ToolName:          e.ToolName,
		ToolID:            e.ToolID,
	})
}

func (l *Logger) forwardSinkEvent(mgr *sinks.Manager, se sinks.Event) {
	if mgr == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	l.forwardSinkEventCtx(ctx, mgr, se)
}

func (l *Logger) forwardSinkEventCtx(ctx context.Context, mgr *sinks.Manager, se sinks.Event) {
	_ = mgr.Forward(ctx, se)
}

// LogActivity [v7, Track 0 stub] records an operator-facing
// mutation — config save, policy reload, block/allow change,
// skill approval, sink change. The activity is persisted to
// activity_events (migration #8) and mirrored onto structured
// emitters as an EventActivity.
//
// This is the Track 0 stub: it accepts the full ActivityInput and
// delegates to LogEvent for the audit_events row. The native
// activity_events write + diff computation land in Track 6 and
// will override this implementation. Parallel tracks may call
// LogActivity today — the audit_events row is still produced, so
// historical queries keep working across the transition.
//
// Callers populate every field; Actor defaults to "system" if
// empty and TargetType / TargetID default to "unknown".
type ActivityInput struct {
	Actor       string
	Action      Action
	TargetType  string
	TargetID    string
	Reason      string
	Before      map[string]any
	After       map[string]any
	Diff        []ActivityDiffEntry
	VersionFrom string
	VersionTo   string
	Severity    string
	RunID       string
	RequestID   string
	TraceID     string
	// SkipSinkFanout avoids re-entrant audit→sink delivery (e.g. circuit-breaker callbacks).
	SkipSinkFanout bool
}

// ActivityDiffEntry mirrors gatewaylog.DiffEntry — kept here so
// audit callers can record diffs without depending on gatewaylog.
type ActivityDiffEntry struct {
	Path   string
	Op     string // add | remove | replace
	Before any
	After  any
}

// LogActivity persists an operator mutation to activity_events (full
// snapshot) and a redacted audit_events summary sharing activity_id.
func (l *Logger) LogActivity(in ActivityInput) error {
	if l == nil {
		return nil
	}
	return l.logActivityImpl(in)
}

// LogAlert [v7, Track 0 stub] records a runtime alert. Alerts are
// the operator-facing signal for "something requires human
// attention" — block lists triggered, scanner crashes, sink
// circuit breaker trips. Backed by audit_events today; parallel
// tracks will tee to OTel event logs and the TUI Alerts panel.
//
// Severity should be one of INFO / WARN / HIGH / CRITICAL. Source
// is a short subsystem name ("admission", "scanner", "sink", etc).
// Summary is a single-line human string; Details is an arbitrary
// map that becomes the details blob.
func (l *Logger) LogAlert(source, severity, summary string, details map[string]any) error {
	if l == nil {
		return nil
	}
	if severity == "" {
		severity = "WARN"
	}
	payload := map[string]any{
		"source":  source,
		"summary": summary,
	}
	for k, v := range details {
		payload[k] = v
	}
	blob, _ := json.Marshal(payload)

	_, otel, emitter := l.snapshot()
	if otel != nil {
		otel.RecordAlert(context.Background(), "runtime", severity, source)
	}
	gwEv := gatewaylog.Event{
		Timestamp: time.Now().UTC(),
		EventType: gatewaylog.EventLifecycle,
		Severity:  parseGatewaySeverity(severity),
		Lifecycle: &gatewaylog.LifecyclePayload{
			Subsystem:  source,
			Transition: "alert",
			Details:    map[string]string{"summary": redaction.ForSinkReason(summary)},
		},
	}
	gwEv.StampProvenance()
	if otel != nil {
		otel.RecordGatewayEvent(gwEv)
	}
	l.emitGatewaySnapshot(emitter, gwEv)

	return l.LogEvent(Event{
		Action:   string(ActionAlert),
		Target:   source,
		Actor:    "defenseclaw",
		Details:  string(blob),
		Severity: severity,
	})
}

// Close flushes and closes every audit sink. Safe to call when no
// sinks are configured. Reads l.sinks under the same lock used by
// setters so Close does not race against SetSinks on a late-stage
// reload. Callers MUST ensure the Logger is drained of in-flight
// LogEvent goroutines before calling Close — this function closes
// the underlying sink manager, which may make subsequent Forward
// calls return errors. That ordering is enforced by sidecar
// shutdown (HTTP listener drained first, then Close).
func (l *Logger) Close() {
	l.mu.RLock()
	mgr := l.sinks
	l.mu.RUnlock()
	if mgr != nil {
		if err := mgr.Close(); err != nil {
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
