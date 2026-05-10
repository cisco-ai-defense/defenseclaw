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
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

// revealHeader is the HTTP header callers set to opt into receiving
// un-redacted finding evidence in the /inspect response body. Every
// request that sets this header is audit-logged with the caller's
// remote address so operators have a trail of who requested raw PII.
//
// Any value other than the exact string "1" is treated as not set;
// this keeps operator fat-fingers (e.g. "true", "yes") from silently
// flipping the switch — the header is an escape hatch, not a mode.
const revealHeader = "X-DefenseClaw-Reveal-PII"

// wantsReveal reports whether the caller has opted into raw PII in
// the HTTP response. Returning true causes the handler to:
//   - emit DetailedFindings with their original Evidence strings,
//   - emit verdict.Reason with the original matched literals,
//   - log an audit event tagged "inspect-reveal" so the choice is
//     discoverable by compliance review.
//
// The persistent-sink invariant is unaffected: SQLite, OTel, and
// webhook payloads still receive redacted content even when a
// caller supplies the header, because those paths don't consult
// this flag.
func wantsReveal(r *http.Request) bool {
	return r.Header.Get(revealHeader) == "1"
}

// ToolInspectRequest is the payload for POST /api/v1/inspect/tool.
// A single endpoint handles both general tool policy checks and message
// content inspection — the handler branches on the Tool field.
type ToolInspectRequest struct {
	Tool            string          `json:"tool"`
	Args            json.RawMessage `json:"args,omitempty"`
	Content         string          `json:"content,omitempty"`
	Direction       string          `json:"direction,omitempty"`
	SessionID       string          `json:"session_id,omitempty"`
	ApprovalSurface string          `json:"approval_surface,omitempty"`
	// Connector selects which connector's rule set the scan uses. The hook
	// handlers stamp it (codex/claudecode/...) so each connector scans
	// against its own EffectiveRulePackDir. Empty ⇒ process-global default
	// set (single-connector installs and the generic inspect endpoint).
	Connector string `json:"connector,omitempty"`
}

// ToolInspectVerdict is the response from the inspect endpoint.
//
// Observe-mode contract:
//
//   - Action is the value the hook script consumes. When the operator
//     has set guardrail.mode=observe (or the per-component mode is
//     not "action"), Action is downgraded to "allow" by applyMode()
//     so the hook script does not exit non-zero, mirroring the
//     evaluate{Codex,ClaudeCode}Hook handlers.
//   - RawAction preserves what the rule scanner would have decided
//     before the mode downgrade, so audit, OTel, and dashboards can
//     still see the latent verdict.
//   - WouldBlock=true means rawAction was "block" but mode≠"action"
//     suppressed the kill switch. Operators reading the response can
//     surface "we would have blocked this" without actually killing
//     the agent's request.
//
// This shape is deliberately the same observe-aware schema the codex
// and claude-code hook responses use so a future generic inspect
// hook script can read .raw_action / .would_block uniformly.
type ToolInspectVerdict struct {
	Action            string        `json:"action"`
	RawAction         string        `json:"raw_action,omitempty"`
	Severity          string        `json:"severity"`
	Confidence        float64       `json:"confidence"`
	Reason            string        `json:"reason"`
	Findings          []string      `json:"findings"`
	DetailedFindings  []RuleFinding `json:"detailed_findings,omitempty"`
	Mode              string        `json:"mode"`
	WouldBlock        bool          `json:"would_block,omitempty"`
	ApprovalTimeoutMS int           `json:"approval_timeout_ms,omitempty"`
}

// applyMode stamps the active guardrail mode onto the verdict and,
// when mode is anything other than "action" (typically "observe"),
// downgrades a "block", "confirm", or "alert" verdict to "allow" while preserving
// the original decision in RawAction and setting WouldBlock for
// "block" downgrades.
//
// The hook scripts at internal/gateway/connector/hooks/inspect-*.sh
// inspect the .action field and exit 2 when it is "block"; the codex
// and claude-code hook handlers already perform an equivalent
// downgrade. Without this helper, operators who configured
// guardrail.mode=observe were silently still being blocked because
// the OpenClaw inspect handlers (handleInspect{Tool,Request,Response,
// ToolResponse}) emitted action=block regardless of mode.
func (v *ToolInspectVerdict) applyMode(mode string) {
	mode = strings.TrimSpace(mode)
	if mode == "" {
		mode = "observe"
	}
	v.Mode = mode
	v.RawAction = v.Action
	if mode == "action" {
		return
	}
	switch v.Action {
	case "block":
		v.WouldBlock = true
		v.Action = "allow"
	case "confirm", "alert":
		v.Action = "allow"
	}
}

// clampPromptDirectionToolVerdict mirrors clampPromptDirectionVerdict for the
// tool-inspect verdict shape used by the connector hook handlers. Done before
// applyMode so the "would-block" telemetry in observe mode reflects the
// already-clamped policy (alert), not the pre-clamp (block/confirm). The
// pre-clamp action is preserved in the verdict's Reason for audit.
//
// CRITICAL severity is exempt from the demotion — see the matching rationale
// on clampPromptDirectionVerdict.
func clampPromptDirectionToolVerdict(verdict *ToolInspectVerdict, direction string) {
	if verdict == nil {
		return
	}
	if guardrailSeverityRank(verdict.Severity) >= severityCritical {
		return
	}
	clamped, demoted := clampPromptDirectionAction(direction, verdict.Action)
	if !demoted {
		return
	}
	original := strings.TrimSpace(verdict.Action)
	verdict.Action = clamped
	verdict.Reason = appendVerdictReason(verdict.Reason,
		fmt.Sprintf("policy-action=%s %s", original, promptSurfaceClampReason))
}

// hookAIDInspect runs the optional Cisco AI Defense lane on the
// hook-side surface (tool calls + tool results + UserPromptSubmit
// for hook-only connectors). Returns nil when the AID lane is off
// (no inspector wired, ScanHookSurface=false, or AID client returns
// nil for any reason — bad payload, transport failure, etc.).
//
// The proxy lane keeps owning chat prompts + completions for
// OpenClaw / ZeptoClaw, so this lane only fires on directions the
// proxy never sees: tool_call, tool_result, and the prompt
// direction emitted from UserPromptSubmit on hook-only connectors.
// Surface gating is intentional — without it, OpenClaw operators
// who set scanner_mode=remote AND configure cisco_ai_defense.api_key
// would double-scan chat traffic (proxy lane + hook lane).
func (a *APIServer) hookAIDInspect(toolName string, content string) *ScanVerdict {
	if a == nil || a.ciscoInspector == nil {
		return nil
	}
	if a.scannerCfg == nil || !a.scannerCfg.CiscoAIDefense.HookSurfaceEnabled() {
		return nil
	}
	if content == "" {
		return nil
	}
	// Prepend the tool name to the content so AID classifiers that
	// match on tool-name strings (e.g. "Limit JIRA actions" /
	// "createJiraIssue") have it visible. AID's /inspect/chat reads
	// content as a free-text user message; the structured tool name
	// would otherwise be lost on the wire.
	body := content
	if toolName != "" && toolName != "message" {
		body = fmt.Sprintf("Tool call: %s\n%s", toolName, content)
	}
	return a.ciscoInspector.Inspect([]ChatMessage{{Role: "user", Content: body}})
}

// mergeWithAIDVerdict folds an AID ScanVerdict into an existing
// ToolInspectVerdict using strictest-wins semantics: action escalates
// (allow → alert → block), severity escalates, findings concatenate.
// Used by the hook-lane callers below.
func mergeWithAIDVerdict(local *ToolInspectVerdict, aid *ScanVerdict) *ToolInspectVerdict {
	if aid == nil {
		return local
	}
	rank := func(action string) int {
		switch strings.ToLower(action) {
		case "block":
			return 3
		case "confirm", "ask":
			return 2
		case "alert":
			return 1
		default:
			return 0
		}
	}
	sevRank := func(s string) int {
		switch strings.ToUpper(s) {
		case "CRITICAL":
			return 4
		case "HIGH":
			return 3
		case "MEDIUM":
			return 2
		case "LOW":
			return 1
		default:
			return 0
		}
	}
	if local == nil {
		local = &ToolInspectVerdict{Action: "allow", Severity: "NONE", Findings: []string{}}
	}
	// AID-only escalation path: escalate the action when AID is
	// stricter, escalate the severity when AID is stricter, append
	// findings + reason so the audit trail shows both lanes.
	if rank(aid.Action) > rank(local.Action) {
		local.Action = aid.Action
	}
	if sevRank(aid.Severity) > sevRank(local.Severity) {
		local.Severity = aid.Severity
	}
	if len(aid.Findings) > 0 {
		// Tag AID findings so operators can tell them apart from
		// regex / CodeGuard hits when reading the audit log.
		for _, f := range aid.Findings {
			local.Findings = append(local.Findings, "ai-defense:"+f)
		}
	}
	if aid.Reason != "" {
		if local.Reason != "" {
			local.Reason = local.Reason + "; " + aid.Reason
		} else {
			local.Reason = aid.Reason
		}
	}
	return local
}

// inspectToolPolicy runs all rule categories against the tool args.
// No tool-name gating — every pattern fires on every tool.
func (a *APIServer) inspectToolPolicy(req *ToolInspectRequest) *ToolInspectVerdict {
	// Static block list takes priority — checked before any rule scanning.
	if a.store != nil {
		if blocked, _ := a.store.HasAction("tool", req.Tool, "install", "block"); blocked {
			return &ToolInspectVerdict{
				Action:     "block",
				Severity:   "HIGH",
				Confidence: 1.0,
				Reason:     fmt.Sprintf("tool %q is on the static block list", req.Tool),
				Findings:   []string{"STATIC-BLOCK"},
			}
		}
	}

	argsStr := string(req.Args)
	toolName := req.Tool

	// Scan against the request connector's rule set so each connector
	// enforces its own pack (empty ⇒ process-global default set).
	ruleFindings := ScanAllRulesForConnector(req.Connector, argsStr, toolName)

	// CodeGuard: scan file content for any file-write tool.
	//
	// Avarice F-3327: the legacy gate matched only the canonical
	// `write_file` / `edit_file` names, but native connector events
	// emit aliases like Claude Code "Write" / "Edit" / "MultiEdit",
	// Codex "patch", and Cursor "applyDiff". Those bypassed CodeGuard
	// entirely while carrying the same code payload. We accept any
	// recognised file-write alias (case-insensitive).
	tool := strings.ToLower(toolName)
	isWriteTool := isWriteToolName(tool)
	var cgFindings []scanner.Finding
	if isWriteTool {
		cgFindings = a.runCodeGuardOnArgs(req)
	}

	if len(ruleFindings) == 0 && len(cgFindings) == 0 {
		// Regex + CodeGuard found nothing locally. Give the AID lane a
		// turn — operators with custom AID policies (e.g. block
		// `createJiraIssue`, throttle `addComment`) want their rules to
		// fire even when no DefenseClaw built-in pattern matched.
		if aid := a.hookAIDInspect(toolName, argsStr); aid != nil && aid.Action != "allow" && aid.Action != "" {
			return mergeWithAIDVerdict(nil, aid)
		}
		return &ToolInspectVerdict{Action: "allow", Severity: "NONE", Findings: []string{}}
	}

	severity := HighestSeverity(ruleFindings)
	confidence := HighestConfidence(ruleFindings, severity)

	for _, cf := range cgFindings {
		if cf.Severity == scanner.SeverityCritical {
			severity = "CRITICAL"
			break
		}
		if cf.Severity == scanner.SeverityHigh && severity != "CRITICAL" {
			severity = "HIGH"
		}
	}

	action := guardrailRuntimeActionForConnector(a.scannerCfg, req.Connector, severity, true)

	reasons := make([]string, 0, minInt(len(ruleFindings), 5))
	for i, f := range ruleFindings {
		if i >= 5 {
			break
		}
		reasons = append(reasons, f.RuleID+":"+f.Title)
	}

	findingStrs := FindingStrings(ruleFindings)
	for _, cf := range cgFindings {
		findingStrs = append(findingStrs, fmt.Sprintf("codeguard:%s:%s", cf.ID, cf.Title))
	}

	verdict := &ToolInspectVerdict{
		Action:           action,
		Severity:         severity,
		Confidence:       confidence,
		Reason:           fmt.Sprintf("matched: %s", strings.Join(reasons, ", ")),
		Findings:         findingStrs,
		DetailedFindings: ruleFindings,
	}

	// AID lane: also forward to Cisco AI Defense when the operator has
	// configured a key. Strictest verdict wins via mergeWithAIDVerdict.
	// We send the rule reasons text rather than just the args because
	// AID's classifier reads free-text content; the rule names give it
	// useful context. The lane is silent when no AID client is wired
	// or when ScanHookSurface=false.
	if aid := a.hookAIDInspect(toolName, argsStr); aid != nil {
		verdict = mergeWithAIDVerdict(verdict, aid)
	}
	return verdict
}

// unmarshalArgsObject decodes a tool-call args payload that may
// arrive either as a JSON object directly OR as a JSON string whose
// content is the object. Avarice F-3328: the managed inspect-tool
// hook builds the request body with `jq --arg args "$TOOL_INPUT"`,
// so well-formed tool input becomes a string field. Returns ok=false
// when neither form yields a non-nil object.
func unmarshalArgsObject(raw json.RawMessage) (map[string]interface{}, bool) {
	if len(raw) == 0 {
		return nil, false
	}
	var asObj map[string]interface{}
	if err := json.Unmarshal(raw, &asObj); err == nil && asObj != nil {
		return asObj, true
	}
	var asStr string
	if err := json.Unmarshal(raw, &asStr); err == nil && asStr != "" {
		var inner map[string]interface{}
		if err := json.Unmarshal([]byte(asStr), &inner); err == nil && inner != nil {
			return inner, true
		}
	}
	return nil, false
}

// isWriteToolName reports whether the lowercased tool name should
// trigger CodeGuard inspection. Avarice F-3327: includes native
// connector aliases that previously bypassed CodeGuard (Write/Edit/
// MultiEdit/applyDiff/patch).
func isWriteToolName(tool string) bool {
	switch tool {
	case "write_file", "edit_file",
		"write", "edit", "multiedit", "multi_edit",
		"applydiff", "apply_diff", "patch",
		"create_file", "createfile", "fs_write", "fs_edit":
		return true
	}
	return false
}

// runCodeGuardOnArgs extracts path/content from write_file/edit_file args
// and runs CodeGuard content scanning.
func (a *APIServer) runCodeGuardOnArgs(req *ToolInspectRequest) []scanner.Finding {
	// Avarice F-3328: the managed inspect-tool hook serializes
	// TOOL_INPUT with `jq -n --arg args "$TOOL_INPUT"`, which yields
	// {"args": "<json-string>"} where `args` is a JSON STRING that
	// itself contains the object. The legacy code unmarshalled
	// req.Args directly into map[string]interface{} and bailed on
	// any error, so the hook path silently skipped CodeGuard. We
	// first try the object form; on failure we attempt to interpret
	// req.Args as a JSON string and unmarshal its contents.
	parsed, ok := unmarshalArgsObject(req.Args)
	if !ok {
		return nil
	}

	filePath, _ := parsed["path"].(string)
	content, _ := parsed["content"].(string)
	if content == "" {
		content, _ = parsed["new_string"].(string)
	}
	if filePath == "" || content == "" {
		// Avarice F-3327: native aliases use different field names.
		if filePath == "" {
			filePath, _ = parsed["file_path"].(string)
		}
		if filePath == "" {
			filePath, _ = parsed["filePath"].(string)
		}
		if content == "" {
			content, _ = parsed["text"].(string)
		}
		if content == "" {
			content, _ = parsed["body"].(string)
		}
	}
	if filePath == "" || content == "" {
		return nil
	}

	if !scanner.IsCodeFile(filepath.Ext(filePath)) {
		return nil
	}

	rulesDir := ""
	if a.scannerCfg != nil {
		rulesDir = a.scannerCfg.Scanners.CodeGuard
	}
	cg := scanner.NewCodeGuardScanner(rulesDir)
	return cg.ScanContent(filePath, content)
}

// inspectMessageContent scans outbound message content for secrets, PII,
// and data exfiltration patterns. Uses the same rule engine.
func (a *APIServer) inspectMessageContent(req *ToolInspectRequest) *ToolInspectVerdict {
	content := req.Content
	if content == "" {
		var parsed map[string]interface{}
		if err := json.Unmarshal(req.Args, &parsed); err == nil {
			if c, ok := parsed["content"].(string); ok {
				content = c
			} else if c, ok := parsed["body"].(string); ok {
				content = c
			}
		}
	}

	if content == "" {
		return &ToolInspectVerdict{Action: "allow", Severity: "NONE", Findings: []string{}}
	}

	// Outbound messages get the full scan — tool name "message" for context.
	// Routed through the request's connector so each connector scans against
	// its own rule pack (empty ⇒ process-global default set).
	ruleFindings := ScanAllRulesForConnector(req.Connector, content, "message")

	if len(ruleFindings) == 0 {
		// Regex found nothing locally. Give the AID lane a turn —
		// custom AID policies (e.g. organisation-specific PII rules)
		// may match where the bundled regex pack didn't.
		if aid := a.hookAIDInspect("message", content); aid != nil && aid.Action != "allow" && aid.Action != "" {
			return mergeWithAIDVerdict(nil, aid)
		}
		return &ToolInspectVerdict{Action: "allow", Severity: "NONE", Findings: []string{}}
	}

	severity := HighestSeverity(ruleFindings)
	confidence := HighestConfidence(ruleFindings, severity)

	action := guardrailRuntimeActionForConnector(a.scannerCfg, req.Connector, severity, strings.EqualFold(req.Direction, "outbound"))

	reasons := make([]string, 0, minInt(len(ruleFindings), 5))
	for i, f := range ruleFindings {
		if i >= 5 {
			break
		}
		reasons = append(reasons, f.RuleID+":"+f.Title)
	}

	verdict := &ToolInspectVerdict{
		Action:           action,
		Severity:         severity,
		Confidence:       confidence,
		Reason:           fmt.Sprintf("matched: %s", strings.Join(reasons, ", ")),
		Findings:         FindingStrings(ruleFindings),
		DetailedFindings: ruleFindings,
	}

	// AID lane: forward the message content to Cisco AI Defense when
	// configured. mergeWithAIDVerdict escalates strictness — AID block
	// trumps regex alert, AID HIGH trumps regex MEDIUM, etc. Lane is a
	// no-op when no client is wired.
	if aid := a.hookAIDInspect("message", content); aid != nil {
		verdict = mergeWithAIDVerdict(verdict, aid)
	}
	return verdict
}

func (a *APIServer) handleInspectTool(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ToolInspectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.Tool == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tool is required"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), inspectScanTimeout)
	defer cancel()

	fmt.Fprintf(os.Stderr, "[inspect] >>> tool=%q args=%s content_len=%d direction=%s\n",
		req.Tool, redaction.MessageContent(string(req.Args)), len(req.Content), req.Direction)

	t0 := time.Now()

	type verdictResult struct {
		v *ToolInspectVerdict
	}
	ch := make(chan verdictResult, 1)
	go func() {
		var v *ToolInspectVerdict
		if strings.ToLower(req.Tool) == "message" && (req.Content != "" || req.Direction == "outbound") {
			v = a.inspectMessageContent(&req)
		} else {
			v = a.inspectToolPolicy(&req)
		}
		ch <- verdictResult{v}
	}()

	var verdict *ToolInspectVerdict
	select {
	case res := <-ch:
		verdict = res.v
	case <-ctx.Done():
		fmt.Fprintf(os.Stderr, "[inspect] tool scan timeout after %s\n", time.Since(t0))
		a.writeJSON(w, http.StatusGatewayTimeout, map[string]string{"error": "scan timeout"})
		return
	}

	verdict.applyMode(inspectMode(a.scannerCfg))
	a.resolveOpenClawInspectConfirm(r.Context(), &req, verdict)

	elapsed := time.Since(t0)

	// verdict.Reason is composed as "matched: <rule-id>:<title>"
	// which is PII-safe by construction (rule metadata only).
	// redaction.Reason is a no-op on it because every token passes
	// the rule-id allow-list — we still route through the helper
	// so any future reason-building logic that embeds literals
	// picks up the scrub automatically.
	fmt.Fprintf(os.Stderr, "[inspect] <<< tool=%q action=%s raw_action=%s severity=%s mode=%s would_block=%v confidence=%.2f elapsed=%s reason=%q findings=%v\n",
		req.Tool, verdict.Action, verdict.RawAction, verdict.Severity, verdict.Mode, verdict.WouldBlock,
		verdict.Confidence, elapsed,
		redaction.Reason(verdict.Reason), verdict.Findings)

	switch verdict.Action {
	case "block":
		fmt.Fprintf(os.Stderr, "[inspect] BLOCKED tool=%q severity=%s reason=%q\n",
			req.Tool, verdict.Severity, redaction.Reason(verdict.Reason))
	case "confirm":
		fmt.Fprintf(os.Stderr, "[inspect] CONFIRM tool=%q severity=%s reason=%q\n",
			req.Tool, verdict.Severity, redaction.Reason(verdict.Reason))
	case "alert":
		fmt.Fprintf(os.Stderr, "[inspect] ALERT tool=%q severity=%s reason=%q\n",
			req.Tool, verdict.Severity, redaction.Reason(verdict.Reason))
	default:
		if verdict.WouldBlock {
			fmt.Fprintf(os.Stderr, "[inspect] OBSERVED tool=%q severity=%s reason=%q (would-block in action mode)\n",
				req.Tool, verdict.Severity, redaction.Reason(verdict.Reason))
		}
	}

	var auditAction string
	switch verdict.Action {
	case "block":
		auditAction = string(audit.ActionInspectToolBlock)
	case "confirm":
		auditAction = string(audit.ActionInspectToolConfirm)
	case "alert":
		auditAction = string(audit.ActionInspectToolAlert)
	default:
		auditAction = string(audit.ActionInspectToolAllow)
	}
	if a.otel != nil {
		elapsedMs := float64(elapsed.Milliseconds())
		tool := a.connectorName() + ":" + req.Tool
		a.otel.RecordInspectEvaluation(context.Background(), tool, verdict.Action, verdict.Severity)
		a.otel.RecordInspectLatency(context.Background(), tool, elapsedMs)
		a.otel.RecordGuardrailEvaluation(context.Background(), a.connectorName()+":policy-rules", verdict.Action)
		a.otel.RecordGuardrailLatency(context.Background(), a.connectorName()+":policy-rules", elapsedMs)
		// Inspect span is emitted for its side effect on the span
		// exporter — trace_id is now pulled from r.Context() by
		// LogActionCtx (the gateway CorrelationMiddleware seeded
		// the same trace id into both).
		_ = a.otel.EmitInspectSpan(context.Background(), req.Tool, verdict.Action, verdict.Severity, elapsedMs)
	}

	targetType := "tool_call"
	if strings.ToLower(req.Tool) == "message" {
		switch strings.ToLower(req.Direction) {
		case "completion", "outbound", "response":
			targetType = "completion"
		case "tool_result", "tool-response":
			targetType = "tool_response"
		default:
			targetType = "prompt"
		}
	}
	evalCtx := a.emitInspectVerdictFindings(r.Context(), "inspect-http",
		"/api/v1/inspect/tool:"+req.Tool, targetType, verdict, elapsed,
		"emit_inspect_tool")

	requestID := RequestIDFromContext(r.Context())
	auditDetails := fmt.Sprintf("severity=%s confidence=%.2f reason=%s elapsed=%s mode=%s would_block=%v raw_action=%s",
		verdict.Severity, verdict.Confidence, verdict.Reason, elapsed, verdict.Mode, verdict.WouldBlock, verdict.RawAction)
	if req.Content != "" {
		auditDetails = appendRawTelemetryDetails(auditDetails, "raw_content", []byte(req.Content))
	}
	if len(req.Args) > 0 {
		auditDetails = appendRawTelemetryDetails(auditDetails, "raw_args", req.Args)
	}
	if requestID != "" {
		auditDetails += fmt.Sprintf(" request_id=%s", requestID)
	}
	auditDetails = appendHookEvaluationDetails(auditDetails, evalCtx)
	_ = a.logger.LogActionCtx(r.Context(), auditAction, req.Tool, auditDetails)

	a.emitCodeGuardOTel(&req, verdict, elapsed)

	// Response-body redaction. By default every Evidence string in
	// DetailedFindings and verdict.Reason are replaced with the
	// ForSinkEvidence/ForSinkReason placeholders so a caller that
	// simply GETs the verdict and logs it cannot accidentally echo
	// user PII. Callers who need raw evidence for triage set
	// X-DefenseClaw-Reveal-PII: 1; we record that fact in the
	// audit store so every reveal is discoverable.
	reveal := wantsReveal(r)
	responseVerdict := verdict.sanitizeForResponse(reveal)
	if reveal {
		// Audit the reveal BEFORE exposing the raw reason. Even
		// when the caller opts in to raw response PII, the
		// audit-store row must still flow through the sink
		// barrier so SQLite/Splunk never see the raw literal.
		_ = a.logger.LogActionCtx(r.Context(), string(audit.ActionInspectReveal), req.Tool,
			fmt.Sprintf("severity=%s remote=%s reason=%s",
				verdict.Severity, r.RemoteAddr,
				redaction.ForSinkReason(verdict.Reason)))
	}
	a.writeJSON(w, http.StatusOK, responseVerdict)
}

func (a *APIServer) resolveOpenClawInspectConfirm(ctx context.Context, req *ToolInspectRequest, verdict *ToolInspectVerdict) {
	if verdict == nil || verdict.Action != guardrailActionConfirm {
		return
	}
	verdict.RawAction = guardrailActionConfirm
	timeout := 60 * time.Second
	if a.scannerCfg != nil && a.scannerCfg.Gateway.ApprovalTimeout > 0 {
		timeout = time.Duration(a.scannerCfg.Gateway.ApprovalTimeout) * time.Second
	}
	verdict.ApprovalTimeoutMS = int(timeout / time.Millisecond)

	// Avarice F-1526: a HIGH-severity tool call that policy escalated
	// to `confirm` MUST NOT be downgraded to `alert` when the caller
	// cannot deliver a human-in-the-loop approval. The previous
	// behavior (alert + would_block=false) caused hook callers that
	// only block on action==block to forward the tool call as audit
	// telemetry. Failing closed here turns "no native approval
	// surface" into a BLOCK with would_block tracking the original
	// confirm decision.
	if !strings.EqualFold(a.connectorName(), "openclaw") {
		verdict.Action = guardrailActionBlock
		verdict.WouldBlock = true
		verdict.Reason = appendVerdictReason(verdict.Reason,
			"human approval unsupported on this connector surface; failing closed (F-1526)")
		if a.logger != nil {
			_ = a.logger.LogActionCtx(ctx, hiltStatusUnsupported, req.Tool, "connector="+a.connectorName())
		}
		return
	}
	if strings.EqualFold(strings.TrimSpace(req.ApprovalSurface), "native") {
		return
	}

	verdict.Action = guardrailActionBlock
	verdict.WouldBlock = true
	verdict.Reason = appendVerdictReason(verdict.Reason,
		"human approval requires native OpenClaw approval; failing closed (F-1526)")
	if a.logger != nil {
		_ = a.logger.LogActionCtx(ctx, hiltStatusUnsupported, req.Tool, "surface="+req.ApprovalSurface)
	}
}

func appendVerdictReason(reason, suffix string) string {
	if strings.TrimSpace(reason) == "" {
		return suffix
	}
	return reason + "; " + suffix
}

// sanitizeForResponse returns a copy of v suitable for the HTTP
// response body. When reveal is false (the default) every Evidence
// field in DetailedFindings is replaced with the
// "<redacted-evidence len=... sha=...>" placeholder AND Reason is
// routed through ForSinkReason. The composed reason is normally
// shaped as "matched: <rule-id>:<title>, …" — ForSinkReason is a
// no-op on that metadata-only shape, but if a scanner ever embeds
// a matched literal in f.Title the sink barrier scrubs it.
//
// The original verdict is left untouched so the audit log, OTel
// spans, and any in-process observers still see the full data
// (which those paths then route through their own ForSink*
// helpers before persistence).
func (v *ToolInspectVerdict) sanitizeForResponse(reveal bool) *ToolInspectVerdict {
	if reveal {
		return v
	}
	cp := *v
	cp.Reason = redaction.ForSinkReason(v.Reason)
	if len(v.DetailedFindings) == 0 {
		return &cp
	}
	cp.DetailedFindings = make([]RuleFinding, len(v.DetailedFindings))
	for i, f := range v.DetailedFindings {
		cp.DetailedFindings[i] = f
		cp.DetailedFindings[i].Evidence = redaction.ForSinkEvidence(f.Evidence, -1, -1)
	}
	return &cp
}

// emitCodeGuardOTel sends OTel signals when CodeGuard findings are present.
func (a *APIServer) emitCodeGuardOTel(req *ToolInspectRequest, verdict *ToolInspectVerdict, elapsed time.Duration) {
	if a.otel == nil {
		return
	}

	tool := strings.ToLower(req.Tool)
	if tool != "write_file" && tool != "edit_file" {
		return
	}

	elapsedMs := float64(elapsed.Milliseconds())

	a.otel.RecordGuardrailEvaluation(context.Background(), "codeguard", verdict.Action)
	a.otel.RecordGuardrailLatency(context.Background(), "codeguard", elapsedMs)

	hasCodeGuardFinding := false
	for _, f := range verdict.Findings {
		if strings.HasPrefix(f, "codeguard:") {
			hasCodeGuardFinding = true
			break
		}
	}

	if !hasCodeGuardFinding {
		return
	}

	if verdict.Action == "block" || verdict.Action == "alert" {
		var filePath string
		var parsed map[string]interface{}
		if err := json.Unmarshal(req.Args, &parsed); err == nil {
			filePath, _ = parsed["path"].(string)
		}

		a.otel.EmitRuntimeAlert(
			telemetry.AlertCodeGuardFinding,
			verdict.Severity,
			telemetry.SourceCodeGuard,
			fmt.Sprintf("CodeGuard: %s", verdict.Reason),
			map[string]string{"tool": req.Tool, "command": filePath},
			map[string]string{"scanner": "codeguard", "action_taken": verdict.Action},
			"", "",
		)
	}
}
