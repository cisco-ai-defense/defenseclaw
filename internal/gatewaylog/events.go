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

// Package gatewaylog defines the structured event schema emitted by
// the DefenseClaw gateway sidecar and the writer stack that persists
// those events to gateway.jsonl / stderr / OTel.
//
// The schema is intentionally small, discriminated, and forward-stable:
// adding a field is non-breaking, renaming a field is breaking. Every
// event carries enough context for incident reconstruction without the
// gateway process running, which is the single hard requirement from
// operators auditing guardrail decisions after the fact.
package gatewaylog

import "time"

// EventType enumerates the five first-class categories of gateway
// observability events. Sinks and filters key off this value.
type EventType string

const (
	// EventVerdict is the terminal decision of a single guardrail
	// pipeline stage (regex, judge, cisco-ai-defense, opa, final).
	// Emitted once per scanner per request in regex_judge mode, and
	// once overall for the composed final verdict.
	EventVerdict EventType = "verdict"

	// EventJudge captures a single LLM-judge invocation — input size,
	// latency, parsed verdict, and (when guardrail.retain_judge_bodies
	// is on) the raw model response. Separated from EventVerdict so
	// Verdict payloads stay small in the hot path.
	EventJudge EventType = "judge"

	// EventLifecycle covers gateway start/stop, config reloads, sink
	// health transitions, and the handful of other non-verdict
	// state changes operators care about.
	EventLifecycle EventType = "lifecycle"

	// EventError is a structured error log. We split errors out of
	// the generic message stream so alerting/pagers can key off a
	// single event_type without grepping free-form strings.
	EventError EventType = "error"

	// EventDiagnostic is a developer-facing trace (init, reentrancy
	// guard fires, provider dial retries). Always ships to stderr
	// but only to sinks when the operator opts in.
	EventDiagnostic EventType = "diagnostic"
)

// Severity is the shared severity vocabulary — keep in lockstep with
// audit.Event severities and OPA policy inputs so downstream filters
// don't need a translation table.
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// Stage identifies which stage of the guardrail pipeline produced a
// Verdict. "final" is the composed result returned to the caller.
type Stage string

const (
	StageRegex    Stage = "regex"
	StageJudge    Stage = "judge"
	StageCiscoAID Stage = "cisco_ai_defense"
	StageOPA      Stage = "opa"
	StageFinal    Stage = "final"
)

// Direction is request-layer (user -> model) vs completion-layer
// (model -> user). Guardrails run on both.
type Direction string

const (
	DirectionPrompt     Direction = "prompt"
	DirectionCompletion Direction = "completion"
)

// Event is the single envelope type every gateway observability
// emission serializes to. Unused fields are omitted to keep JSONL
// lines compact; indexers then key on event_type to interpret the
// type-specific payload in the `verdict`, `judge`, `lifecycle`, and
// `error` sub-objects.
type Event struct {
	// Envelope fields — always populated.
	Timestamp time.Time `json:"ts"`
	EventType EventType `json:"event_type"`
	Severity  Severity  `json:"severity"`
	RunID     string    `json:"run_id,omitempty"`
	RequestID string    `json:"request_id,omitempty"`
	SessionID string    `json:"session_id,omitempty"`
	Provider  string    `json:"provider,omitempty"`
	Model     string    `json:"model,omitempty"`
	Direction Direction `json:"direction,omitempty"`

	// Type-specific payloads — exactly one is populated.
	Verdict    *VerdictPayload    `json:"verdict,omitempty"`
	Judge      *JudgePayload      `json:"judge,omitempty"`
	Lifecycle  *LifecyclePayload  `json:"lifecycle,omitempty"`
	Error      *ErrorPayload      `json:"error,omitempty"`
	Diagnostic *DiagnosticPayload `json:"diagnostic,omitempty"`
}

// VerdictPayload describes a single pipeline stage decision.
// Structured findings live on JudgePayload (or on the pipeline-level
// audit record). This envelope carries only the decision and a
// redacted, operator-facing reason — enough to drive the TUI and
// SIEM without re-deriving shape for every sink.
type VerdictPayload struct {
	Stage      Stage    `json:"stage"`
	Action     string   `json:"action"`               // allow | warn | block
	Reason     string   `json:"reason,omitempty"`     // short, redacted
	Categories []string `json:"categories,omitempty"` // e.g. [pii.email, injection.system_prompt]
	LatencyMs  int64    `json:"latency_ms,omitempty"`
}

// Finding matches the shape guardrail scanners emit. Keep the field
// set minimal — additional context belongs in the stage-specific
// JudgePayload or VerdictPayload, not here.
type Finding struct {
	Category   string   `json:"category"`
	Severity   Severity `json:"severity"`
	Rule       string   `json:"rule,omitempty"`
	Evidence   string   `json:"evidence,omitempty"` // always redacted to a safe preview
	Confidence float64  `json:"confidence,omitempty"`
	Source     string   `json:"source,omitempty"` // regex | judge | cisco_aid
}

// JudgePayload records a single LLM-judge call. RawResponse is only
// populated when guardrail.retain_judge_bodies is true — operators
// opt in because raw bodies can echo user PII.
type JudgePayload struct {
	Kind        string    `json:"kind"` // injection | pii | tool_injection
	Model       string    `json:"model"`
	InputBytes  int       `json:"input_bytes"`
	LatencyMs   int64     `json:"latency_ms"`
	Action      string    `json:"action,omitempty"`
	Severity    Severity  `json:"severity,omitempty"`
	Findings    []Finding `json:"findings,omitempty"`
	RawResponse string    `json:"raw_response,omitempty"`
	ParseError  string    `json:"parse_error,omitempty"`
}

// LifecyclePayload covers sidecar start/stop and config-reload
// transitions. Details is free-form and always redacted.
type LifecyclePayload struct {
	Subsystem  string            `json:"subsystem"`  // gateway | watcher | sinks | telemetry | api
	Transition string            `json:"transition"` // start | stop | ready | degraded | restored
	Details    map[string]string `json:"details,omitempty"`
}

// ErrorPayload is the structured shape of every recoverable error we
// want an operator to be able to filter on. Non-recoverable errors
// exit the process and land in stderr before the sidecar dies.
type ErrorPayload struct {
	Subsystem string `json:"subsystem"`
	Code      string `json:"code,omitempty"` // stable short identifier
	Message   string `json:"message"`
	Cause     string `json:"cause,omitempty"`
}

// DiagnosticPayload carries developer traces that don't fit the other
// categories. Message is human-readable; Fields is an open bag.
type DiagnosticPayload struct {
	Component string                 `json:"component"`
	Message   string                 `json:"message"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
}
