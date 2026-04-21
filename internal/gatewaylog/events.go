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

import (
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/version"
)

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

	// EventScan [v7] is a per-scan completion summary emitted by
	// skill / mcp / plugin / aibom / codeguard scanners. Carries
	// scanner identity, target, duration, finding counts by
	// severity, and the parent scan_id. One per scan invocation.
	EventScan EventType = "scan"

	// EventScanFinding [v7] is a per-finding event fanned out
	// alongside EventScan so SIEM consumers can alert on a single
	// critical finding without having to join against the scan
	// summary. Emitted once per Finding; a scan that produces N
	// findings therefore produces 1 EventScan + N EventScanFinding.
	EventScanFinding EventType = "scan_finding"

	// EventActivity [v7] records operator-facing mutations:
	// config updates, policy reloads, block/allow list changes,
	// skill approval, sink reconfiguration. Carries a full
	// before/after snapshot plus a compact structured diff so
	// compliance auditors can reconstruct every change without
	// scraping CLI output.
	EventActivity EventType = "activity"
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
// type-specific payload in the `verdict`, `judge`, `lifecycle`,
// `error`, `scan`, `scan_finding`, and `activity` sub-objects.
//
// v7 additions:
//   - Provenance (schema_version + content_hash + generation +
//     binary_version) is stamped on EVERY event via StampProvenance
//     at the writer choke point. Downstream consumers use it to
//     distinguish between two events emitted by the same sidecar
//     across a config reload, and to reject events they can't parse.
//   - Agent identity is three-tiered: AgentID (logical, stable
//     across restarts), AgentInstanceID (per agent session),
//     SidecarInstanceID (per sidecar process, stable UUID minted
//     at boot). All three coexist; aggregates key off different
//     tiers for different questions.
//   - EventScan/EventScanFinding/EventActivity expand the payload
//     union with full scanner and operator-mutation coverage.
//
// Nullability:
//   - Envelope fields marked `omitempty` are OPTIONAL per event type.
//     Never assume a given event carries ToolName/PolicyID/etc.
//     Consult docs/event-contracts.md for the field-presence matrix.
type Event struct {
	// Envelope fields — always populated.
	Timestamp time.Time `json:"ts"`
	EventType EventType `json:"event_type"`
	Severity  Severity  `json:"severity"`

	// Provenance quartet (v7). Populated at the writer choke point
	// via StampProvenance; callers should leave these zero and let
	// the writer fill them so every event on a single wire reflects
	// a consistent snapshot of config state. SchemaVersion is always
	// emitted (current contract: 7) so consumers can branch on the
	// envelope version without probing optional fields. Generation
	// is likewise always emitted — a zero value is semantically
	// meaningful ("no bumps observed yet"), not missing data.
	SchemaVersion int    `json:"schema_version"`
	ContentHash   string `json:"content_hash,omitempty"`
	Generation    uint64 `json:"generation"`
	BinaryVersion string `json:"binary_version,omitempty"`

	// Correlation
	RunID     string `json:"run_id,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	// TraceID mirrors the OTel span's trace id for cross-sink
	// correlation. Optional — unset events are still valid.
	TraceID   string    `json:"trace_id,omitempty"`
	Provider  string    `json:"provider,omitempty"`
	Model     string    `json:"model,omitempty"`
	Direction Direction `json:"direction,omitempty"`

	// Agent/tool/policy correlation fields. All are optional
	// because not every event type populates every field:
	// guardrail verdicts carry Model+Provider but no ToolName,
	// tool_call events carry ToolName+ToolID but no Model, etc.
	// Downstream consumers must tolerate missing fields gracefully.
	//
	// Three-tier agent identity (v7):
	//
	//   - AgentID: logical agent name/ID. Stable across restarts,
	//     across sidecar processes, and across agent instances.
	//     Use this to group "all events for agent X" in dashboards.
	//   - AgentInstanceID: a single agent execution / session.
	//     Stable per conversation; changes when the agent is
	//     re-invoked. Use this to group turns within one
	//     conversation.
	//   - SidecarInstanceID: the sidecar process. Stable for the
	//     sidecar's lifetime; changes on every restart. Primarily
	//     useful for operators debugging which sidecar emitted a
	//     specific event.
	AgentID           string `json:"agent_id,omitempty"`
	AgentName         string `json:"agent_name,omitempty"`
	AgentInstanceID   string `json:"agent_instance_id,omitempty"`
	SidecarInstanceID string `json:"sidecar_instance_id,omitempty"`
	PolicyID          string `json:"policy_id,omitempty"`
	DestinationApp    string `json:"destination_app,omitempty"`
	ToolName          string `json:"tool_name,omitempty"`
	ToolID            string `json:"tool_id,omitempty"`

	// Multi-tenant / fleet-scoping fields (v7 reserved, unpopulated).
	//
	// These are intentionally declared ahead of the code paths that
	// will set them so the wire format is forward-stable: a rolling
	// fleet upgrade can ship a new sidecar that emits these attributes
	// without forcing every indexer/SIEM to relearn the schema. All
	// five are `omitempty` — until the corresponding producer lights
	// them up they stay off the wire and off the JSON line entirely.
	//
	//   - TenantID: logical tenancy boundary for hosted / SaaS
	//     deployments. One DefenseClaw sidecar can front agents owned
	//     by multiple tenants; this field makes per-tenant billing,
	//     auth scoping, and SIEM routing deterministic.
	//   - WorkspaceID: sub-tenant scope (Slack-style workspace,
	//     organization, or team). Allows the TUI / Grafana to filter
	//     down from a tenant to a single working group.
	//   - Environment: deployment environment string
	//     (dev | staging | prod | sandbox). Dashboards key off it
	//     so SLO alerts for "prod" don't fire on dev noise.
	//   - DeploymentMode: mode the sidecar is running in
	//     (standalone | managed | edge | ci). Helps operators
	//     distinguish between agent events emitted from developer
	//     laptops vs production fleets vs ephemeral CI runs.
	//   - DiscoverySource: how the sidecar learned about the
	//     monitored agent/tool (registry | manual | scan | import).
	//     Feeds asset-management systems without a separate discovery
	//     table.
	//
	// NOTE: do NOT populate these until the matching producer lands.
	// They are declared here so every downstream consumer (gateway.jsonl
	// indexer, audit sinks, OTLP translator, TUI parser, Splunk HEC
	// adapter) can safely pass them through today and start projecting
	// them once a producer ships.
	TenantID        string `json:"tenant_id,omitempty"`
	WorkspaceID     string `json:"workspace_id,omitempty"`
	Environment     string `json:"environment,omitempty"`
	DeploymentMode  string `json:"deployment_mode,omitempty"`
	DiscoverySource string `json:"discovery_source,omitempty"`

	// Type-specific payloads — exactly one is populated.
	Verdict     *VerdictPayload     `json:"verdict,omitempty"`
	Judge       *JudgePayload       `json:"judge,omitempty"`
	Lifecycle   *LifecyclePayload   `json:"lifecycle,omitempty"`
	Error       *ErrorPayload       `json:"error,omitempty"`
	Diagnostic  *DiagnosticPayload  `json:"diagnostic,omitempty"`
	Scan        *ScanPayload        `json:"scan,omitempty"`
	ScanFinding *ScanFindingPayload `json:"scan_finding,omitempty"`
	Activity    *ActivityPayload    `json:"activity,omitempty"`
}

// StampProvenance fills the four v7 provenance fields from the
// current process-wide snapshot. Safe to call more than once; later
// calls override earlier values so the writer can stamp at the
// final serialization hop without worrying about upstream staleness.
// Intended to be invoked at the writer choke point, never at the
// emission call site, so a single wire run shows consistent
// schema/content/generation across all events.
func (e *Event) StampProvenance() {
	p := version.Current()
	e.SchemaVersion = p.SchemaVersion
	e.ContentHash = p.ContentHash
	e.Generation = p.Generation
	e.BinaryVersion = p.BinaryVersion
}

// sidecarInstanceID is the per-process stable identifier stamped on
// every event whose caller did not set one. The sidecar boot path
// populates it alongside audit.SetProcessAgentInstanceID; leaving it
// unset is only expected in unit tests where the identifier is
// irrelevant.
var sidecarInstanceID atomic.Value

// SetSidecarInstanceID installs the per-process sidecar UUID that
// the writer will stamp on events lacking an explicit value. Pairs
// with audit.SetProcessAgentInstanceID — kept in a separate package
// to avoid a gateway → audit cycle at the writer level.
func SetSidecarInstanceID(id string) {
	sidecarInstanceID.Store(id)
}

// SidecarInstanceID returns the installed per-process sidecar UUID
// or the empty string when boot hasn't set one yet.
func SidecarInstanceID() string {
	v, _ := sidecarInstanceID.Load().(string)
	return v
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
//
// v7 additions: RuleID + LineNumber. Scanner-origin findings
// (skill/plugin/mcp/aibom/codeguard) always populate RuleID so
// downstream SIEM can group by detection rule without brittle
// substring matches on Rule. LineNumber is the 1-based source line
// or 0 when not meaningful (e.g. file-level findings).
type Finding struct {
	Category   string   `json:"category"`
	Severity   Severity `json:"severity"`
	Rule       string   `json:"rule,omitempty"`
	RuleID     string   `json:"rule_id,omitempty"`
	LineNumber int      `json:"line_number,omitempty"`
	Evidence   string   `json:"evidence,omitempty"` // always redacted to a safe preview
	Confidence float64  `json:"confidence,omitempty"`
	Source     string   `json:"source,omitempty"` // regex | judge | cisco_aid | skill | mcp | plugin | aibom | codeguard
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
	Transition string            `json:"transition"` // start | stop | ready | degraded | restored | alert | completed
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

// ScanPayload [v7] summarises a single scanner invocation.
// Findings live on sibling EventScanFinding events for SIEM
// per-row alerting; this payload carries the roll-up counts.
//
// ScanID correlates a ScanPayload to its children; every
// ScanFindingPayload tied to the same scan shares a ScanID.
type ScanPayload struct {
	ScanID      string         `json:"scan_id"`
	Scanner     string         `json:"scanner"` // skill | mcp | plugin | aibom | codeguard
	Target      string         `json:"target"`  // file path | skill name | server URL
	TargetType  string         `json:"target_type,omitempty"`
	Verdict     string         `json:"verdict,omitempty"` // clean | warn | block
	DurationMs  int64          `json:"duration_ms,omitempty"`
	SeverityMax Severity       `json:"severity_max,omitempty"`
	Counts      map[string]int `json:"counts,omitempty"` // severity -> count
	TotalCount  int            `json:"total_count,omitempty"`
	ExitCode    int            `json:"exit_code,omitempty"`
	Error       string         `json:"error,omitempty"` // scanner execution error
}

// ScanFindingPayload [v7] records a single finding produced by a
// scanner. Downstream SIEM can alert on severity/rule_id without
// joining to the parent ScanPayload.
type ScanFindingPayload struct {
	ScanID      string   `json:"scan_id"`
	Scanner     string   `json:"scanner"`
	Target      string   `json:"target"`
	FindingID   string   `json:"finding_id,omitempty"`
	RuleID      string   `json:"rule_id,omitempty"`
	Category    string   `json:"category,omitempty"`
	Title       string   `json:"title,omitempty"`
	Description string   `json:"description,omitempty"` // redacted
	Severity    Severity `json:"severity,omitempty"`
	Location    string   `json:"location,omitempty"` // redacted path + line
	LineNumber  int      `json:"line_number,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// ActivityPayload [v7] records an operator-facing mutation
// (config save, policy reload, block/allow list update, skill
// approval). Before/After are compact JSON snapshots of the changed
// resource; Diff is a structured key-level diff so dashboards
// don't have to diff blobs themselves.
//
// Actor is the principal who made the change (CLI user, automated
// watcher, HTTP API client). Reason is operator-supplied free text.
// TargetType + TargetID identify what changed (policy/skill/mcp/
// config/action/sink).
type ActivityPayload struct {
	Actor       string         `json:"actor"`
	Action      string         `json:"action"` // mirrors audit.Action
	TargetType  string         `json:"target_type"`
	TargetID    string         `json:"target_id"`
	Reason      string         `json:"reason,omitempty"`
	Before      map[string]any `json:"before,omitempty"` // nil on create
	After       map[string]any `json:"after,omitempty"`  // nil on delete
	Diff        []DiffEntry    `json:"diff,omitempty"`
	VersionFrom string         `json:"version_from,omitempty"`
	VersionTo   string         `json:"version_to,omitempty"`
}

// DiffEntry is a single added / removed / changed key within an
// ActivityPayload. For array fields Path uses "field[index]"
// notation; for nested maps a dotted path is used.
type DiffEntry struct {
	Path   string `json:"path"`
	Op     string `json:"op"` // add | remove | replace
	Before any    `json:"before,omitempty"`
	After  any    `json:"after,omitempty"`
}
