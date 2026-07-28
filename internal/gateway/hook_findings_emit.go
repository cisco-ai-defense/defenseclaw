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
	"context"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// hookEvaluationContext carries the per-evaluation correlation
// state that hook handlers stamp on both the JSON response (new
// optional fields, additive — old clients ignore them) and the
// audit log (key=value suffix appended to the existing details
// string). All fields are optional; an empty struct represents a
// no-findings evaluation that does not need stamping.
type hookEvaluationContext struct {
	// EvaluationID is the join key shared by scan_findings rows
	// and the matching audit row. Empty when no findings were
	// emitted (so audit detail stays unchanged).
	EvaluationID string
	// ScanID joins the evaluation summary to its per-finding rows.
	ScanID string
	// RuleIDs are the top detection rule_ids that drove this
	// evaluation, capped so SIEM queries don't explode.
	RuleIDs []string
}

// emitHookRuleFindings fans the verdict's DetailedFindings through the audit
// logger's canonical v8 scan boundary so the per-rule matches are observable
// through routed logs, forensic scan rows, generated dashboard metrics, and
// the sliding-window correlator without per-surface fanout.
//
// Returns the empty struct when verdict has no detailed findings,
// so callers can use the result unconditionally:
//
//	eval := a.emitHookRuleFindings(ctx, "claudecode", req.HookEventName,
//	    verdict, "tool_call", elapsed)
//	details = appendHookEvaluationDetails(details, eval)
//	resp.EvaluationID = eval.EvaluationID
//	resp.RuleIDs = eval.RuleIDs
//
// Best-effort: emission errors are swallowed and logged via the
// underlying telemetry sink — the hook response must never fail
// because the observability pipeline hiccupped.
func (a *APIServer) emitHookRuleFindings(
	ctx context.Context,
	connector, hookEvent string,
	verdict *ToolInspectVerdict,
	targetType string,
	latency time.Duration,
) hookEvaluationContext {
	return a.emitInspectVerdictFindings(ctx, "hook-rules", hookEvaluationTarget(connector, hookEvent),
		targetType, verdict, latency, "emit_hook_findings")
}

// emitInspectVerdictFindings is the shared body of every
// runtime finding emitter on the gateway side (hook handlers,
// /api/v1/inspect/* HTTP endpoints, proxy mid-stream / tool-call
// inspect). It fans verdict.DetailedFindings through
// the canonical generated scan pipeline under the supplied scanner enum,
// stamps correlation IDs from the request context, and returns
// the evaluation_id + top rule_ids for the caller to surface in
// audit details + response payloads.
//
// Best-effort: emission errors are recorded via the generated scan-error
// metric (errorReason as the bounded error label) and the function
// returns an empty hookEvaluationContext so the upstream code
// path is never aborted by a telemetry hiccup.
func (a *APIServer) emitInspectVerdictFindings(
	ctx context.Context,
	scannerEnum, target, targetType string,
	verdict *ToolInspectVerdict,
	latency time.Duration,
	errorReason string,
) hookEvaluationContext {
	if verdict == nil || len(verdict.DetailedFindings) == 0 {
		return hookEvaluationContext{}
	}

	inspectFindings := ruleFindingsToInspect(verdict.DetailedFindings)
	src := scanner.InspectFindingSource{
		Scanner:    scannerEnum,
		Target:     target,
		TargetType: targetType,
		Verdict:    verdict.Action,
		DurationMs: latency.Milliseconds(),
		Findings:   inspectFindings,
	}

	if a.logger == nil {
		return hookEvaluationContext{}
	}
	evalID, scanID, err := a.logger.LogInspectFindingsWithCorrelation(ctx, src, ScanCorrelationFromContext(ctx))
	if err != nil {
		metricRuntime, _ := a.observabilityV8RuntimeEmitter().(hookLifecycleMetricV8Runtime)
		recordScanErrorV8(ctx, metricRuntime, "gateway.runtime.findings", src.Scanner, src.TargetType, errorReason)
		return hookEvaluationContext{}
	}
	return hookEvaluationContext{
		EvaluationID: evalID,
		ScanID:       scanID,
		RuleIDs:      scanner.TopRuleIDs(inspectFindings, 8),
	}
}

// emitGuardrailScanVerdictFindings is the proxy-side companion of
// emitInspectVerdictFindings: it fans a *ScanVerdict (which carries
// only stringy Findings, not structured DetailedFindings) through
// the same canonical pipeline so per-rule runtime detections from the
// guardrail proxy (prompt + completion + mid-stream + tool-call inspect) land
// on every configured observability destination.
//
// Synthesis path: NormalizeScanVerdict already maps raw finding
// strings to a stable canonical_id + category + severity + title
// (+ confidence when the source detector reported one). We treat
// each canonical_id as a rule_id so SIEM dashboards can pivot on
// "rule_id=pii.email" across hook + proxy + inspect surfaces.
//
// Returns an empty struct (and emits nothing) when:
//   - verdict is nil, or
//   - verdict has no findings (NormalizeScanVerdict returned nil),
//     so the metrics/correlator pipelines stay focused on real
//     detections instead of "no-finding" rollups.
func (p *GuardrailProxy) emitGuardrailScanVerdictFindings(
	ctx context.Context,
	scannerEnum, target, targetType string,
	verdict *ScanVerdict,
	latency time.Duration,
	errorReason string,
) hookEvaluationContext {
	if verdict == nil {
		return hookEvaluationContext{}
	}
	normalized := NormalizeScanVerdict(verdict)
	if len(normalized) == 0 {
		return hookEvaluationContext{}
	}
	inspectFindings := normalizedFindingsToInspect(normalized, verdict.Severity)
	src := scanner.InspectFindingSource{
		ScanID:       verdict.ScanID,
		Scanner:      scannerEnum,
		Target:       target,
		TargetType:   targetType,
		Verdict:      verdict.Action,
		DurationMs:   latency.Milliseconds(),
		EvaluationID: verdict.EvaluationID,
		Findings:     inspectFindings,
	}
	if p.logger == nil {
		return hookEvaluationContext{}
	}
	evalID, scanID, err := p.logger.LogInspectFindingsWithCorrelation(ctx, src, ScanCorrelationFromContext(ctx))
	if err != nil {
		metricRuntime, _ := p.observabilityV8TraceRuntime().(hookLifecycleMetricV8Runtime)
		recordScanErrorV8(ctx, metricRuntime, "gateway.runtime.findings", src.Scanner, src.TargetType, errorReason)
		return hookEvaluationContext{}
	}
	return hookEvaluationContext{
		EvaluationID: evalID,
		ScanID:       scanID,
		RuleIDs:      scanner.TopRuleIDs(inspectFindings, 8),
	}
}

// normalizedFindingsToInspect adapts NormalizedFinding records
// (the canonical-ID view of a ScanVerdict's raw finding strings)
// into the scanner.InspectFinding shape that EmitInspectFindings
// understands. The canonical_id becomes rule_id so SIEM dashboards
// can pivot on a single field across hook + inspect + proxy
// surfaces.
//
// fallbackSeverity is the verdict-level severity; per-finding
// severity overrides it when the normalizer captured one. Empty
// titles fall back to the canonical ID so the EventScanFinding
// payload never has an empty Title field on the wire.
func normalizedFindingsToInspect(nfs []NormalizedFinding, fallbackSeverity string) []scanner.InspectFinding {
	if len(nfs) == 0 {
		return nil
	}
	out := make([]scanner.InspectFinding, 0, len(nfs))
	for _, nf := range nfs {
		sev := nf.Severity
		if sev == "" {
			sev = fallbackSeverity
		}
		title := nf.Title
		if title == "" {
			title = nf.CanonicalID
		}
		var tags []string
		if strings.TrimSpace(nf.Category) != "" {
			tags = []string{nf.Category}
		}
		out = append(out, scanner.InspectFinding{
			RuleID:     nf.CanonicalID,
			Title:      title,
			Severity:   scanner.Severity(sev),
			Confidence: nf.Confidence,
			Tags:       tags,
		})
	}
	return out
}

// emitAssetPolicyDecisionFindings adapts a single asset-policy
// decision into the unified scan_findings pipeline so registry /
// blocklist / admin-deny enforcement events are observable on the
// same surfaces as hook + proxy + inspect detections.
//
// The decision is synthesized into a single InspectFinding because
// asset-policy is a binary match-or-miss check (one verdict per
// asset), not a multi-rule scan. We encode the registry provenance
// (decision.Source, RegistryStatus, RegistryConfigured) into the
// finding's Tags so SIEM queries can pivot on
// "tag=registry-required" without re-parsing the audit details
// string. The rule_id is composed as
// "asset_policy.<target_type>.<source>" so the metric
// defenseclaw_scan_findings_by_rule_total has stable, scoped
// labels (asset_policy.skill.registry-required,
// asset_policy.mcp.admin-deny, etc.).
//
// Returns an empty hookEvaluationContext when no canonical logger is wired or
// the decision is not a real asset-policy match (callers already pre-filter to
// RawAction==block, but the guard keeps the helper defensive
// against future call sites).
func (a *APIServer) emitAssetPolicyDecisionFindings(
	ctx context.Context,
	decision config.AssetPolicyDecision,
	targetType, connector, hookEvent string,
) hookEvaluationContext {
	if strings.TrimSpace(decision.RawAction) == "" {
		return hookEvaluationContext{}
	}
	ruleID := assetPolicyDecisionRuleID(decision, targetType)
	title := assetPolicyDecisionTitle(decision)
	finding := scanner.InspectFinding{
		RuleID:   ruleID,
		Title:    title,
		Severity: "HIGH",
		Tags:     assetPolicyDecisionTags(decision),
	}
	src := scanner.InspectFindingSource{
		Scanner:    "asset-policy",
		Target:     hookEvaluationTarget(connector, hookEvent),
		TargetType: hookTargetTypeForEvent(hookEvent),
		Verdict:    decision.Action,
		Findings:   []scanner.InspectFinding{finding},
	}
	if a.logger == nil {
		return hookEvaluationContext{}
	}
	evalID, scanID, err := a.logger.LogInspectFindingsWithCorrelation(ctx, src, ScanCorrelationFromContext(ctx))
	if err != nil {
		metricRuntime, _ := a.observabilityV8RuntimeEmitter().(hookLifecycleMetricV8Runtime)
		recordScanErrorV8(ctx, metricRuntime, "gateway.runtime.findings", src.Scanner, src.TargetType, "emit_asset_policy")
		return hookEvaluationContext{}
	}
	return hookEvaluationContext{
		EvaluationID: evalID,
		ScanID:       scanID,
		RuleIDs:      []string{ruleID},
	}
}

// assetPolicyDecisionRuleID composes the canonical rule identifier
// used in scan_findings rows and the EventScanFinding payload for
// an asset-policy decision. The shape is intentionally namespaced
// so SIEM rules can match on the prefix:
//
//	asset_policy.<target_type>.<source>
//
// target_type defaults to "asset" when the decision didn't carry
// one (defensive — every call site sets one today). source
// defaults to "match" when decision.Source is blank to avoid a
// trailing-dot rule_id that complicates metric labels.
func assetPolicyDecisionRuleID(decision config.AssetPolicyDecision, targetType string) string {
	tt := strings.ToLower(strings.TrimSpace(targetType))
	if tt == "" {
		tt = strings.ToLower(strings.TrimSpace(decision.TargetType))
	}
	if tt == "" {
		tt = "asset"
	}
	src := strings.TrimSpace(decision.Source)
	if src == "" {
		src = "match"
	}
	return "asset_policy." + tt + "." + src
}

// assetPolicyDecisionTitle picks the most operator-friendly text
// for the EventScanFinding's Title field: prefer the decision's
// human reason, fall back to the target name, then a generic
// label. Title rendering downstream (TUI, Splunk) only shows the
// first ~80 chars, so longer reasons get truncated implicitly.
func assetPolicyDecisionTitle(decision config.AssetPolicyDecision) string {
	if strings.TrimSpace(decision.Reason) != "" {
		return strings.TrimSpace(decision.Reason)
	}
	if strings.TrimSpace(decision.TargetName) != "" {
		return strings.TrimSpace(decision.TargetName)
	}
	return "asset policy violation"
}

// assetPolicyDecisionTags packs registry provenance + runtime
// surface signals into the InspectFinding.Tags slice so SIEM
// queries can filter on
// `tag=registry-required AND tag=mcp`-style combinations without
// parsing audit details strings. Empty values are dropped so the
// emitted payload stays compact.
func assetPolicyDecisionTags(decision config.AssetPolicyDecision) []string {
	var tags []string
	if v := strings.TrimSpace(decision.Source); v != "" {
		tags = append(tags, v)
	}
	if v := strings.TrimSpace(decision.RegistryStatus); v != "" {
		tags = append(tags, "registry_status="+v)
	}
	if v := strings.TrimSpace(decision.RuntimeSurface); v != "" {
		tags = append(tags, "surface="+v)
	}
	if decision.RegistryConfigured {
		tags = append(tags, "registry_configured=true")
	} else {
		tags = append(tags, "registry_configured=false")
	}
	if decision.WouldBlock {
		tags = append(tags, "would_block=true")
	}
	return tags
}

// emitToolCallInspectFindings runs the structured RuleFinding[] from
// inspectToolCalls through the canonical v8 scan boundary under
// scanner="tool-call-inspect". The proxy already has the full
// per-rule structure (RuleID, Severity, Confidence, Evidence,
// Tags), so we adapt directly via ruleFindingsToInspect instead of
// going through NormalizeScanVerdict's stringy round-trip.
//
// Returns the resulting evaluation_id + top rule_ids so the
// caller can stamp them on its audit row + ScanVerdict. Errors are
// recorded via the generated scan-error metric under
// "emit_tool_call_inspect" and result in an empty
// hookEvaluationContext so the upstream code path is unaffected.
func (p *GuardrailProxy) emitToolCallInspectFindings(
	ctx context.Context,
	allFindings []RuleFinding,
	action string,
) hookEvaluationContext {
	if len(allFindings) == 0 {
		return hookEvaluationContext{}
	}
	inspectFindings := ruleFindingsToInspect(allFindings)
	src := scanner.InspectFindingSource{
		Scanner:    "tool-call-inspect",
		Target:     p.connectorName() + ":tool-call",
		TargetType: "tool_call",
		Verdict:    action,
		Findings:   inspectFindings,
	}
	if p.logger == nil {
		return hookEvaluationContext{}
	}
	evalID, scanID, err := p.logger.LogInspectFindingsWithCorrelation(ctx, src, ScanCorrelationFromContext(ctx))
	if err != nil {
		metricRuntime, _ := p.observabilityV8TraceRuntime().(hookLifecycleMetricV8Runtime)
		recordScanErrorV8(ctx, metricRuntime, "gateway.runtime.findings", src.Scanner, src.TargetType, "emit_tool_call_inspect")
		return hookEvaluationContext{}
	}
	return hookEvaluationContext{
		EvaluationID: evalID,
		ScanID:       scanID,
		RuleIDs:      scanner.TopRuleIDs(inspectFindings, 8),
	}
}

// recordTelemetryScannerEnum picks the scanner-enum label that
// best describes the proxy-side guardrail emission feeding into
// the unified scan_findings pipeline.
//
//   - direction == "tool-call"  → "tool-call-inspect"
//   - direction == "completion" and elapsed == 0 (the convention
//     used by the streaming mid-stream / early-block branches that
//     call recordTelemetry with elapsed=0 because the latency is
//     not measured at that point) → "mid-stream"
//   - everything else (prompt + post-stream completion verdicts)
//     → "guardrail-llm"
//
// Centralizing the mapping keeps SIEM filters like
// `scanner="mid-stream"` reliably equivalent across the four
// recordTelemetry call sites in proxy.go.
func recordTelemetryScannerEnum(direction string, verdict *ScanVerdict, elapsed time.Duration) string {
	switch strings.TrimSpace(direction) {
	case "tool-call", "tool_call":
		return "tool-call-inspect"
	case "completion":
		if elapsed == 0 {
			return "mid-stream"
		}
	}
	_ = verdict
	return "guardrail-llm"
}

// recordTelemetryTarget builds the target string used in the
// scan_results / EventScan rows for proxy guardrail emissions.
// The model name is the most useful field for SIEM queries
// (e.g. "block rate per model"), with a "direction:" prefix so a
// single model_id surfaces separately on prompt vs completion vs
// tool-call surfaces.
func recordTelemetryTarget(direction, model string) string {
	d := strings.TrimSpace(direction)
	if d == "" {
		d = "unknown"
	}
	m := strings.TrimSpace(model)
	if m == "" {
		m = "unknown"
	}
	return d + ":" + m
}

// recordTelemetryTargetType maps the proxy guardrail's direction
// label onto the v7 scan-event schema's target_type enum.
func recordTelemetryTargetType(direction string) string {
	switch strings.TrimSpace(direction) {
	case "prompt":
		return "prompt"
	case "completion":
		return "completion"
	case "tool-call", "tool_call":
		return "tool_call"
	default:
		return "inspect"
	}
}

// hookTargetTypeForEvent returns the v7 gateway-event schema
// target_type enum value that best describes the hook event:
//
//   - prompt-shaped events (UserPromptSubmit, UserMessage, etc.)
//     map to "prompt"
//   - tool-invocation events (PreToolUse, PermissionRequest, etc.)
//     map to "tool_call"
//   - tool-result events (PostToolUse, PostToolUseFailure, etc.)
//     map to "tool_response"
//   - assistant-output / completion events map to "completion"
//   - everything else (SessionStart, Stop, etc.) falls back to
//     "inspect"
//
// Keeping the mapping centralized means SIEM filters like
// `target_type="prompt"` work uniformly across all hook
// connectors (claudecode, codex, agent-hook, etc.).
func hookTargetTypeForEvent(hookEvent string) string {
	switch strings.TrimSpace(hookEvent) {
	case "UserPromptSubmit", "UserPromptExpansion", "UserMessage",
		"InstructionsLoaded", "ConfigChange", "FileChanged",
		"Elicitation", "ElicitationResult", "Notification",
		"TaskCreated", "TeammateIdle", "PreCompact":
		return "prompt"
	case "PreToolUse", "PermissionRequest", "PermissionDenied",
		"ToolUse", "ToolCall":
		return "tool_call"
	case "PostToolUse", "PostToolUseFailure", "PostToolBatch",
		"ToolResult":
		return "tool_response"
	case "AssistantResponse", "Completion":
		return "completion"
	default:
		return "inspect"
	}
}

// hookEvaluationTarget builds the canonical "connector:hookEvent"
// target used by every hook-derived scan event. Empty parts default
// to "unknown" so the writer's schema gate never sees an empty
// target string.
func hookEvaluationTarget(connector, hookEvent string) string {
	connector = strings.TrimSpace(connector)
	if connector == "" {
		connector = "unknown"
	}
	hookEvent = strings.TrimSpace(hookEvent)
	if hookEvent == "" {
		hookEvent = "unknown"
	}
	return connector + ":" + hookEvent
}

// ruleFindingsToInspect adapts gateway.RuleFinding into the
// scanner-package-neutral InspectFinding shape that
// EmitInspectFindings understands. RuleFinding.Evidence is
// already redacted upstream by the rules engine, so this is a
// pure structural copy — no additional sanitization.
func ruleFindingsToInspect(in []RuleFinding) []scanner.InspectFinding {
	if len(in) == 0 {
		return nil
	}
	out := make([]scanner.InspectFinding, 0, len(in))
	for _, f := range in {
		out = append(out, scanner.InspectFinding{
			RuleID:              f.RuleID,
			Title:               f.Title,
			Severity:            scanner.Severity(f.Severity),
			Confidence:          f.Confidence,
			Evidence:            f.Evidence,
			Tags:                f.Tags,
			ToolCapabilityClass: f.ToolCapabilityClass,
		})
	}
	return out
}

// appendHookEvaluationDetails appends `evaluation_id=<uuid>` and
// `rule_ids=<id1,id2,...>` to an existing key=value audit detail
// string in a strictly additive way: pre-existing log parsers
// keep matching the same prefix, and the new fields can be
// extracted by a simple `grep -oE 'evaluation_id=[a-z0-9-]+'`.
func appendHookEvaluationDetails(details string, eval hookEvaluationContext) string {
	if eval.EvaluationID == "" && len(eval.RuleIDs) == 0 {
		return details
	}
	parts := make([]string, 0, 3)
	if strings.TrimSpace(details) != "" {
		parts = append(parts, details)
	}
	if eval.EvaluationID != "" {
		parts = append(parts, "evaluation_id="+eval.EvaluationID)
	}
	if len(eval.RuleIDs) > 0 {
		parts = append(parts, "rule_ids="+strings.Join(eval.RuleIDs, ","))
	}
	return strings.Join(parts, " ")
}
