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
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

// gatewayEvents is the process-wide structured event writer. It is
// installed by the sidecar boot path and consumed by the verdict /
// judge / lifecycle emission helpers in this package.
//
// A nil writer is a valid "events disabled" state — every helper
// checks for nil so unit tests and libraries that import internal/
// gateway without running the sidecar can no-op cleanly.
var (
	gatewayEventsMu sync.RWMutex
	gatewayEvents   *gatewaylog.Writer

	// judgePersistor is an optional hook invoked for every Judge
	// event when guardrail.retain_judge_bodies is on and the
	// sidecar wired up a persistence callback. Left nil in unit
	// tests and in the "retention off" path.
	judgePersistor func(gatewaylog.JudgePayload)
)

// SetJudgePersistor installs the optional SQLite persistence hook
// invoked from emitJudge when retention is enabled. Passing nil
// disables persistence (safe default).
func SetJudgePersistor(fn func(gatewaylog.JudgePayload)) {
	gatewayEventsMu.Lock()
	defer gatewayEventsMu.Unlock()
	judgePersistor = fn
}

// judgePersist returns the currently installed persistor (may be nil).
func judgePersist() func(gatewaylog.JudgePayload) {
	gatewayEventsMu.RLock()
	defer gatewayEventsMu.RUnlock()
	return judgePersistor
}

// SetEventWriter installs the process-wide gatewaylog.Writer. The
// sidecar calls this exactly once, right after the writer is
// constructed, before any request handling begins.
func SetEventWriter(w *gatewaylog.Writer) {
	gatewayEventsMu.Lock()
	defer gatewayEventsMu.Unlock()
	gatewayEvents = w
}

// EventWriter returns the active writer (may be nil).
func EventWriter() *gatewaylog.Writer {
	gatewayEventsMu.RLock()
	defer gatewayEventsMu.RUnlock()
	return gatewayEvents
}

// emitEvent is the low-level helper that all other emitters delegate
// to. It enforces the "gateway.jsonl (and every downstream OTel /
// Splunk / webhook fan-out) never sees unredacted PII" invariant by
// scrubbing caller-supplied free-form strings here. Rule IDs and
// canonical IDs survive (ForSinkReason/ForSinkString preserve the
// metadata token shape); matched literals are masked with a
// deterministic hash prefix so operators can still correlate.
//
// Copy-on-write discipline: every payload struct that we need to
// mutate is shallow-copied before we touch its fields, so a caller
// that kept a reference to the original (e.g. for a subsequent
// audit.Log call) does NOT observe the redacted values. The
// scrubbing here is a sink-only transform.
//
// Lifecycle.Details and Diagnostic.Fields are NOT redacted. Those
// bags carry operator-authored metadata — ports, file paths,
// version strings, subsystem names — which operators need in the
// clear to triage incidents. Redacting them turns every startup
// event into an opaque smear of `<redacted len=6 sha=…>`
// placeholders, breaking the primary use case for structured
// lifecycle logs. If a caller ever needs to put user-provided
// content into one of these fields they must run it through the
// appropriate redaction helper before the emit.
func emitEvent(e gatewaylog.Event) {
	w := EventWriter()
	if w == nil {
		return
	}
	if v := e.Verdict; v != nil {
		cp := *v
		cp.Reason = redaction.ForSinkReason(cp.Reason)
		e.Verdict = &cp
	}
	if j := e.Judge; j != nil {
		cp := *j
		// RawResponse routinely echoes the triggering
		// prompt verbatim — sinks must only ever see the
		// redacted form. ParseError is short caller-owned
		// metadata but we redact it too in case a parser
		// embeds a snippet of the offending body.
		cp.RawResponse = redaction.ForSinkString(cp.RawResponse)
		cp.ParseError = redaction.ForSinkString(cp.ParseError)
		e.Judge = &cp
	}
	if er := e.Error; er != nil {
		cp := *er
		cp.Message = redaction.ForSinkString(cp.Message)
		cp.Cause = redaction.ForSinkString(cp.Cause)
		e.Error = &cp
	}
	w.Emit(e)
}

// emitVerdict records a single guardrail-pipeline stage decision.
func emitVerdict(
	stage gatewaylog.Stage,
	direction gatewaylog.Direction,
	model string,
	action, reason string,
	severity gatewaylog.Severity,
	categories []string,
	latencyMs int64,
) {
	emitEvent(gatewaylog.Event{
		EventType: gatewaylog.EventVerdict,
		Severity:  severity,
		Direction: direction,
		Model:     model,
		Verdict: &gatewaylog.VerdictPayload{
			Stage:      stage,
			Action:     action,
			Reason:     reason,
			Categories: categories,
			LatencyMs:  latencyMs,
		},
	})
}

// emitJudge records a single LLM-judge invocation. raw may be empty
// when guardrail.retain_judge_bodies is off — the writer still emits
// the surrounding metadata (latency, model, verdict) so operators
// can see judge health without inspecting PII-heavy bodies.
func emitJudge(
	kind, model string,
	direction gatewaylog.Direction,
	inputBytes int,
	latencyMs int64,
	action string,
	severity gatewaylog.Severity,
	parseError string,
	raw string,
) {
	payload := gatewaylog.JudgePayload{
		Kind:        kind,
		Model:       model,
		InputBytes:  inputBytes,
		LatencyMs:   latencyMs,
		Action:      action,
		Severity:    severity,
		ParseError:  parseError,
		RawResponse: raw,
	}

	// SQLite persistence runs first because emitEvent mutates its own
	// shallow copy of the payload (it scrubs RawResponse before
	// forwarding to the sinks pipeline). We want the local,
	// operator-owned store to receive the un-redacted body — retention
	// is explicit opt-in via guardrail.retain_judge_bodies and the SQLite
	// file is already covered by the same filesystem ACLs as the rest
	// of ~/.defenseclaw.
	if persist := judgePersist(); persist != nil && raw != "" {
		persist(payload)
	}

	emitEvent(gatewaylog.Event{
		EventType: gatewaylog.EventJudge,
		Severity:  severity,
		Direction: direction,
		Model:     model,
		Judge:     &payload,
	})
}

// emitLifecycle records a sidecar state change. Details is free-form
// caller-owned metadata — put path/port/version in here, not in the
// message field.
func emitLifecycle(subsystem, transition string, details map[string]string) {
	emitEvent(gatewaylog.Event{
		EventType: gatewaylog.EventLifecycle,
		Lifecycle: &gatewaylog.LifecyclePayload{
			Subsystem:  subsystem,
			Transition: transition,
			Details:    details,
		},
	})
}

// emitError records a structured gateway error. Prefer this over
// fmt.Fprintf(defaultLogWriter, ...) for anything that should surface
// in /health or alerting — stderr-only diagnostics stay in the
// legacy writer.
func emitError(subsystem, code, message string, cause error) {
	payload := &gatewaylog.ErrorPayload{
		Subsystem: subsystem,
		Code:      code,
		Message:   message,
	}
	if cause != nil {
		payload.Cause = cause.Error()
	}
	emitEvent(gatewaylog.Event{
		EventType: gatewaylog.EventError,
		Severity:  gatewaylog.SeverityHigh,
		Error:     payload,
	})
}

// emitDiagnostic records a structured debug-level event. Use this
// for request-scoped state transitions that operators may want to
// replay (e.g. "regex produced N signals, routing to judge") — not
// for noisy per-byte traces.
//
// The gatewaylog.DiagnosticPayload schema uses {Component, Fields}
// (Fields is an open typed bag). Callers pass a simple string map
// for ergonomics; we widen it to interface{} here.
func emitDiagnostic(component, message string, details map[string]string) {
	var fields map[string]interface{}
	if len(details) > 0 {
		fields = make(map[string]interface{}, len(details))
		for k, v := range details {
			fields[k] = v
		}
	}
	emitEvent(gatewaylog.Event{
		EventType: gatewaylog.EventDiagnostic,
		Severity:  gatewaylog.SeverityInfo,
		Diagnostic: &gatewaylog.DiagnosticPayload{
			Component: component,
			Message:   message,
			Fields:    fields,
		},
	})
}

// deriveSeverity maps an audit.Event severity string into the strict
// gatewaylog.Severity type. Unknown strings fall back to INFO rather
// than panicking so we never lose an event to an enum mismatch.
func deriveSeverity(s string) gatewaylog.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return gatewaylog.SeverityCritical
	case "HIGH":
		return gatewaylog.SeverityHigh
	case "MEDIUM":
		return gatewaylog.SeverityMedium
	case "LOW":
		return gatewaylog.SeverityLow
	default:
		return gatewaylog.SeverityInfo
	}
}
