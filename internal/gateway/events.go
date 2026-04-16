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
)

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
// to. Keeping it in one place means we pick up timestamp defaulting,
// sev normalization, and future redaction hooks for free.
func emitEvent(e gatewaylog.Event) {
	w := EventWriter()
	if w == nil {
		return
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
	emitEvent(gatewaylog.Event{
		EventType: gatewaylog.EventJudge,
		Severity:  severity,
		Direction: direction,
		Model:     model,
		Judge: &gatewaylog.JudgePayload{
			Kind:        kind,
			Model:       model,
			InputBytes:  inputBytes,
			LatencyMs:   latencyMs,
			Action:      action,
			Severity:    severity,
			ParseError:  parseError,
			RawResponse: raw,
		},
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
