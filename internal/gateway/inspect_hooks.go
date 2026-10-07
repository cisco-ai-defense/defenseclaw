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
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/google/uuid"
)

// inspectMode returns the operator-selected guardrail mode (action or
// observe) that handleInspect{Request,Response,ToolResponse} use to
// drive the ToolInspectVerdict.applyMode downgrade.
//
// Mirroring evaluateCodexHook / evaluateClaudeCodeHook semantics:
//   - nil/zero config → "observe" (fail-safe-for-the-user)
//   - explicit "" or whitespace → "observe"
//   - any value other than "action" → "observe" so the only path
//     that actually blocks the agent is the explicit operator opt-in.
func inspectMode(cfg *config.Config) string {
	mode := ""
	if cfg != nil {
		mode = strings.TrimSpace(cfg.Guardrail.Mode)
	}
	if mode != "action" {
		return "observe"
	}
	return mode
}

const (
	maxInspectContentLen = 256 * 1024 // 256 KiB per field
	// inspectScanTimeout caps every synchronous rule scan executed under
	// /api/v1/inspect/*. The hook callers (claude-code, codex, inspect-tool)
	// are in the agent's critical path: a timeout here directly stalls the
	// user-visible LLM call. Plan F19 sets this to 200ms — fast enough that
	// a stuck regex / pathological scanner can never wedge the agent, while
	// still covering >P99 of well-behaved scans (median is well under 5ms
	// for the rule set shipped in internal/gateway/scan_rules*.go).
	inspectScanTimeout = 200 * time.Millisecond
)

// scanWithTimeout runs ScanAllRules under a context deadline. Returns partial
// results if the deadline fires — the caller should treat a timeout as a
// high-severity finding.
func scanWithTimeout(ctx context.Context, text, toolName string, timeout time.Duration) ([]RuleFinding, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ch := make(chan []RuleFinding, 1)
	go func() {
		ch <- scanAllRulesFor(ctx, text, toolName)
	}()
	select {
	case findings := <-ch:
		return findings, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func truncateInspectContent(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}

func (a *APIServer) recordManagedAIDFailOpenForSelectedGenericResult(
	ctx context.Context,
	verdict *ToolInspectVerdict,
) {
	if verdict == nil || verdict.Action != "allow" {
		return
	}
	metricCtx, cancelMetric := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	a.recordManagedAIDFailOpenVerdict(metricCtx, verdict)
	cancelMetric()
}

// RequestInspectRequest is the payload for POST /api/v1/inspect/request.
// Called before the user query is sent to the LLM.
type RequestInspectRequest struct {
	Content   string `json:"content"`
	Model     string `json:"model,omitempty"`
	SessionID string `json:"session_id,omitempty"`
}

// ResponseInspectRequest is the payload for POST /api/v1/inspect/response.
// Called after the LLM returns a response.
type ResponseInspectRequest struct {
	Content   string `json:"content"`
	Model     string `json:"model,omitempty"`
	SessionID string `json:"session_id,omitempty"`
}

// ToolResponseInspectRequest is the payload for POST /api/v1/inspect/tool-response.
// Called after a tool finishes execution, before the result is fed back to the LLM.
type ToolResponseInspectRequest struct {
	Tool      string          `json:"tool"`
	Output    json.RawMessage `json:"output,omitempty"`
	ExitCode  int             `json:"exit_code,omitempty"`
	SessionID string          `json:"session_id,omitempty"`
}

// handleInspectRequest inspects user query content before it is sent to the LLM.
func (a *APIServer) handleInspectRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RequestInspectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	req.Content = truncateInspectContent(req.Content, maxInspectContentLen)
	managedAIDOnly := a.managedAIDOnly()
	if req.Content == "" && !managedAIDOnly {
		a.writeJSON(w, http.StatusOK, &ToolInspectVerdict{Action: "allow", Severity: "NONE", Findings: []string{}})
		return
	}

	fmt.Fprintf(os.Stderr, "[inspect] >>> pre-request content_len=%d model=%s\n",
		len(req.Content), req.Model)

	t0 := time.Now()

	var verdict *ToolInspectVerdict
	if managedAIDOnly {
		verdict = a.inspectManagedAIDOnly(
			deferManagedAIDFailOpenAccounting(r.Context()), "message", req.Content,
		)
	} else {
		ruleFindings, err := scanWithTimeout(r.Context(), req.Content, "user-request", inspectScanTimeout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[inspect] pre-request scan timeout after %s\n", time.Since(t0))
			a.writeJSON(w, http.StatusGatewayTimeout, map[string]string{"error": "scan timeout"})
			return
		}
		// A prompt block stands: guardrail.block_at is one threshold on every
		// surface. A prompt is never confirmable, so there is no confirm to
		// demote.
		verdict = a.buildVerdict(r.Context(), ruleFindings, "prompt", false)
	}
	verdict.applyMode(inspectMode(a.decisionConfig(r.Context())))

	elapsed := time.Since(t0)

	fmt.Fprintf(os.Stderr, "[inspect] <<< pre-request action=%s raw_action=%s severity=%s mode=%s would_block=%v elapsed=%s reason=%q\n",
		verdict.Action, verdict.RawAction, verdict.Severity, verdict.Mode, verdict.WouldBlock, elapsed,
		redaction.Reason(verdict.Reason))

	if verdict.Action == "block" {
		fmt.Fprintf(os.Stderr, "[inspect] BLOCKED pre-request severity=%s reason=%q\n",
			verdict.Severity, redaction.Reason(verdict.Reason))
	} else if verdict.WouldBlock {
		fmt.Fprintf(os.Stderr, "[inspect] OBSERVED pre-request severity=%s reason=%q (would-block in action mode)\n",
			verdict.Severity, redaction.Reason(verdict.Reason))
	}

	auditAction := "inspect-request-" + verdict.Action
	connectorName := a.connectorName()
	a.recordInspectMetricsV8(
		r.Context(), connectorName, connectorName+":pre-request",
		verdict.Action, verdict.Severity, elapsed,
	)

	evalCtx := a.emitInspectVerdictFindings(r.Context(), "inspect-http",
		"/api/v1/inspect/request", "prompt", verdict, elapsed, "emit_inspect_request")
	a.emitInspectTraceV8(r.Context(), "", "prompt", verdict, elapsed, evalCtx)

	requestID := RequestIDFromContext(r.Context())
	auditDetails := fmt.Sprintf("severity=%s elapsed=%s mode=%s would_block=%v raw_action=%s model=%s",
		verdict.Severity, elapsed, verdict.Mode, verdict.WouldBlock, verdict.RawAction, req.Model)
	if requestID != "" {
		auditDetails += fmt.Sprintf(" request_id=%s", requestID)
	}
	auditDetails = appendHookEvaluationDetails(auditDetails, evalCtx)
	_ = a.logger.LogEventCtx(r.Context(), a.inspectAuditEvent(r, "/api/v1/inspect/request", auditAction, "pre-request", auditDetails))

	reveal := wantsReveal(r)
	if managedAIDOnly {
		a.recordManagedAIDFailOpenForSelectedGenericResult(r.Context(), verdict)
	}
	a.writeJSON(w, http.StatusOK, verdict.sanitizeForResponse(reveal))
}

// handleInspectResponse inspects LLM response content after it is returned.
func (a *APIServer) handleInspectResponse(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ResponseInspectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	req.Content = truncateInspectContent(req.Content, maxInspectContentLen)
	managedAIDOnly := a.managedAIDOnly()
	if req.Content == "" && !managedAIDOnly {
		a.writeJSON(w, http.StatusOK, &ToolInspectVerdict{Action: "allow", Severity: "NONE", Findings: []string{}})
		return
	}

	fmt.Fprintf(os.Stderr, "[inspect] >>> post-response content_len=%d model=%s\n",
		len(req.Content), req.Model)

	t0 := time.Now()

	var verdict *ToolInspectVerdict
	if managedAIDOnly {
		verdict = a.inspectManagedAIDOnly(
			deferManagedAIDFailOpenAccounting(r.Context()), "message", req.Content,
		)
	} else {
		ruleFindings, err := scanWithTimeout(r.Context(), req.Content, "llm-response", inspectScanTimeout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[inspect] post-response scan timeout after %s\n", time.Since(t0))
			a.writeJSON(w, http.StatusGatewayTimeout, map[string]string{"error": "scan timeout"})
			return
		}
		verdict = a.buildVerdict(r.Context(), ruleFindings, "completion", false)
	}
	verdict.applyMode(inspectMode(a.decisionConfig(r.Context())))

	elapsed := time.Since(t0)

	fmt.Fprintf(os.Stderr, "[inspect] <<< post-response action=%s raw_action=%s severity=%s mode=%s would_block=%v elapsed=%s reason=%q\n",
		verdict.Action, verdict.RawAction, verdict.Severity, verdict.Mode, verdict.WouldBlock, elapsed,
		redaction.Reason(verdict.Reason))

	if verdict.Action == "block" {
		fmt.Fprintf(os.Stderr, "[inspect] BLOCKED post-response severity=%s reason=%q\n",
			verdict.Severity, redaction.Reason(verdict.Reason))
	} else if verdict.WouldBlock {
		fmt.Fprintf(os.Stderr, "[inspect] OBSERVED post-response severity=%s reason=%q (would-block in action mode)\n",
			verdict.Severity, redaction.Reason(verdict.Reason))
	}

	auditAction := "inspect-response-" + verdict.Action
	connectorName := a.connectorName()
	a.recordInspectMetricsV8(
		r.Context(), connectorName, connectorName+":post-response",
		verdict.Action, verdict.Severity, elapsed,
	)

	evalCtx := a.emitInspectVerdictFindings(r.Context(), "inspect-http",
		"/api/v1/inspect/response", "completion", verdict, elapsed, "emit_inspect_response")
	a.emitInspectTraceV8(r.Context(), "", "completion", verdict, elapsed, evalCtx)

	requestID := RequestIDFromContext(r.Context())
	auditDetails := fmt.Sprintf("severity=%s elapsed=%s mode=%s would_block=%v raw_action=%s model=%s",
		verdict.Severity, elapsed, verdict.Mode, verdict.WouldBlock, verdict.RawAction, req.Model)
	if requestID != "" {
		auditDetails += fmt.Sprintf(" request_id=%s", requestID)
	}
	auditDetails = appendHookEvaluationDetails(auditDetails, evalCtx)
	_ = a.logger.LogEventCtx(r.Context(), a.inspectAuditEvent(r, "/api/v1/inspect/response", auditAction, "post-response", auditDetails))

	reveal := wantsReveal(r)
	if managedAIDOnly {
		a.recordManagedAIDFailOpenForSelectedGenericResult(r.Context(), verdict)
	}
	a.writeJSON(w, http.StatusOK, verdict.sanitizeForResponse(reveal))
}

// handleInspectToolResponse inspects tool execution output before it is fed back to the LLM.
func (a *APIServer) handleInspectToolResponse(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ToolResponseInspectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.Tool == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tool is required"})
		return
	}

	managedAIDOnly := a.managedAIDOnly()
	outputStr := string(req.Output)
	if managedAIDOnly {
		var semanticOutput string
		if err := json.Unmarshal(req.Output, &semanticOutput); err == nil {
			outputStr = semanticOutput
		}
	}
	outputStr = truncateInspectContent(outputStr, maxInspectContentLen)

	fmt.Fprintf(os.Stderr, "[inspect] >>> post-tool tool=%q output_len=%d exit_code=%d\n",
		req.Tool, len(outputStr), req.ExitCode)

	t0 := time.Now()

	var verdict *ToolInspectVerdict
	if managedAIDOnly {
		aidContent := outputStr
		if strings.TrimSpace(outputStr) != "" {
			aidContent = fmt.Sprintf("Tool call: %s\n%s", req.Tool, outputStr)
		}
		verdict = a.inspectManagedAIDOnly(
			deferManagedAIDFailOpenAccounting(r.Context()), "message", aidContent,
		)
	} else {
		ruleFindings, err := scanWithTimeout(r.Context(), outputStr, req.Tool+"-response", inspectScanTimeout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[inspect] post-tool scan timeout after %s\n", time.Since(t0))
			a.writeJSON(w, http.StatusGatewayTimeout, map[string]string{"error": "scan timeout"})
			return
		}
		verdict = a.buildVerdict(r.Context(), ruleFindings, "tool_response", false)

		// Judge lane (J3-3c/J3-3d): the generic /inspect/tool-response
		// endpoint was regex-only. Forward the tool output to the LLM judge
		// for connectors opted into the completion direction via
		// guardrail.judge.hook_connectors + EffectiveStrategy("completion").
		// Tool output is completion-shaped (matches the proxy lane's
		// inspectToolResult). This is the J3-3c timeout split: the regex
		// scan above keeps the 200ms inspectScanTimeout cap, while the judge
		// runs on a deadline-free context bounded only by its own
		// HookTimeout. WithoutCancel keeps the request's caller identity and
		// correlation so the judge span stays attributable (GAP-2641). The
		// shipped default (regex_only) ⇒ no judge call.
		// ToolResponseInspectRequest carries no connector field, so the gate
		// resolves the process connector via connectorName().
		if jv := a.runHookJudge(context.WithoutCancel(r.Context()), "completion", "completion",
			a.connectorName(), outputStr, req.Tool, verdict); jv != nil {
			verdict = mergeWithJudgeVerdict(verdict, jv)
		}
	}

	verdict.applyMode(inspectMode(a.decisionConfig(r.Context())))

	elapsed := time.Since(t0)

	fmt.Fprintf(os.Stderr, "[inspect] <<< post-tool tool=%q action=%s raw_action=%s severity=%s mode=%s would_block=%v elapsed=%s reason=%q\n",
		req.Tool, verdict.Action, verdict.RawAction, verdict.Severity, verdict.Mode, verdict.WouldBlock, elapsed,
		redaction.Reason(verdict.Reason))

	if verdict.Action == "block" {
		fmt.Fprintf(os.Stderr, "[inspect] BLOCKED post-tool tool=%q severity=%s reason=%q\n",
			req.Tool, verdict.Severity, redaction.Reason(verdict.Reason))
	} else if verdict.WouldBlock {
		fmt.Fprintf(os.Stderr, "[inspect] OBSERVED post-tool tool=%q severity=%s reason=%q (would-block in action mode)\n",
			req.Tool, verdict.Severity, redaction.Reason(verdict.Reason))
	}

	auditAction := "inspect-tool-response-" + verdict.Action
	connectorName := a.connectorName()
	a.recordInspectMetricsV8(
		r.Context(), connectorName, connectorName+":post-tool-"+req.Tool,
		verdict.Action, verdict.Severity, elapsed,
	)

	evalCtx := a.emitInspectVerdictFindings(r.Context(), "inspect-http",
		"/api/v1/inspect/tool-response:"+req.Tool, "tool_response", verdict, elapsed,
		"emit_inspect_tool_response")
	a.emitInspectTraceV8(r.Context(), req.Tool, "tool_response", verdict, elapsed, evalCtx)

	requestID := RequestIDFromContext(r.Context())
	auditDetails := fmt.Sprintf("tool=%s severity=%s elapsed=%s mode=%s would_block=%v raw_action=%s exit_code=%d",
		req.Tool, verdict.Severity, elapsed, verdict.Mode, verdict.WouldBlock, verdict.RawAction, req.ExitCode)
	if requestID != "" {
		auditDetails += fmt.Sprintf(" request_id=%s", requestID)
	}
	auditDetails = appendHookEvaluationDetails(auditDetails, evalCtx)
	_ = a.logger.LogEventCtx(r.Context(), a.inspectAuditEvent(r, "/api/v1/inspect/tool-response", auditAction, req.Tool, auditDetails))
	if !managedAIDOnly {
		a.alertSensitiveToolResult(r, req.Tool, outputStr, verdict)
	}

	reveal := wantsReveal(r)
	if managedAIDOnly {
		a.recordManagedAIDFailOpenForSelectedGenericResult(r.Context(), verdict)
	}
	a.writeJSON(w, http.StatusOK, verdict.sanitizeForResponse(reveal))
}

// alertSensitiveToolResult raises tool-result-pii-alert for a tool result on
// the generic inspect endpoint; see sensitiveToolResultAlert.
func (a *APIServer) alertSensitiveToolResult(r *http.Request, tool, output string, verdict *ToolInspectVerdict) {
	if verdict == nil || a.logger == nil {
		return
	}
	details, ok := a.sensitiveToolResultAlert(r.Context(), profileRequestConnector(r.Context()), tool, verdict.Severity, verdict.Findings, output)
	if !ok {
		return
	}
	event := a.inspectAuditEvent(
		r, "/api/v1/inspect/tool-response", string(audit.ActionToolResultPIIAlert), tool, details)
	a.raiseToolResultAlert(r.Context(), event, verdict.Severity)
}

// alertSensitiveHookToolResult is the same alert for the connector hook
// endpoints (Claude Code, Codex and every other agent hook), which finalize
// their tool results through finalizeAgentHook instead of the inspect route.
func (a *APIServer) alertSensitiveHookToolResult(ctx context.Context, connectorName string, req agentHookRequest, resp agentHookResponse) {
	if a.logger == nil || a.managedAIDOnly() || req.ToolName == "" || !isResultLikeEvent(req.HookEventName) {
		return
	}
	result := stringifyHookValue(firstValue(req.Payload, "tool_response", "toolResponse", "tool_result", "toolResult", "result", "error"))
	details, ok := a.sensitiveToolResultAlert(ctx, connectorName, req.ToolName, resp.Severity, resp.Findings, result)
	if !ok {
		return
	}
	structured := map[string]any{"route": "hook:" + req.HookEventName, "connector": connectorName}
	auditCallerIdentity(ctx).addTo(structured)
	a.raiseToolResultAlert(ctx, audit.Event{
		Action:     string(audit.ActionToolResultPIIAlert),
		Target:     req.ToolName,
		Details:    details,
		Connector:  connectorName,
		Structured: structured,
	}, resp.Severity)
}

// raiseToolResultAlert files a tool-result-pii-alert with the severity of the
// result's findings and sends it to the configured webhooks. The row used to
// carry INFO, which the alert views leave out, so the alert was an audit row
// no operator saw (GAP-0187). The details only count the findings.
func (a *APIServer) raiseToolResultAlert(ctx context.Context, event audit.Event, findingSeverity string) {
	event.Severity = toolResultAlertSeverity(findingSeverity)
	// The logger stamps the row id on its own copy of the event, so give the
	// event its id first: the webhook payload then carries the id of the audit
	// row, and the delivery can be matched to the alert (GAP-0218).
	if event.ID == "" {
		event.ID = uuid.New().String()
	}
	_ = a.logger.LogEventCtx(ctx, event)
	if a.webhookSource == nil {
		return
	}
	if webhooks := a.webhookSource(); webhooks != nil {
		event.Timestamp = time.Now().UTC()
		event.Actor = "defenseclaw-hook"
		event.Structured = nil
		webhooks.Dispatch(event)
	}
}

// toolResultAlertSeverity maps a findings severity to the outer severity of
// the alert row: one the alert views list (never INFO or NONE).
func toolResultAlertSeverity(severity string) string {
	switch s := strings.ToUpper(strings.TrimSpace(severity)); s {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW":
		return s
	default:
		return "MEDIUM"
	}
}

// sensitiveToolResultAlert checks the same composed rule pack and entity rules
// that scanned this request. Findings from a judge or another category do not
// prove a sensitive value; only matched entity values count.
func (a *APIServer) sensitiveToolResultAlert(ctx context.Context, connectorName, tool, severity string, findings []string, output string) (string, bool) {
	g := a.generation()
	if g == nil {
		return "", false
	}
	pack := g.RulePacks["conn:"+connectorName]
	if pack == nil {
		pack = g.RulePacks["global"]
	}
	if g.Profiles != nil {
		resolved := resolvedGuardrailProfileFrom(ctx)
		if resolved == nil || resolved.set != g.Profiles {
			resolved = resolveGuardrailProfileFor(ctx, g.Profiles)
		}
		if resolved != nil && resolved.derived != nil {
			key := effectiveRulePackKey(resolved.derived, connectorName)
			if key != effectiveRulePackKey(g.Profiles.base, connectorName) {
				if selected := g.Profiles.packs[key]; selected != nil {
					pack = selected
				} else if retry := g.Profiles.missing[key]; retry != nil {
					if selected := retry.pack(time.Now()); selected != nil {
						pack = selected
					}
				}
			}
		}
	}
	entry := pack.LookupSensitiveTool(tool)
	if entry == nil || !entry.ResultInspection {
		return "", false
	}
	minEntities := entry.MinEntitiesAlert
	if minEntities <= 0 {
		minEntities = 1
	}
	entities := countRuleEntitiesFor(ctx, connectorName, output)
	if entities == 0 && output != "" {
		// A judge can identify PII that has no deterministic pattern. Only
		// its PII findings may stand in for matched values.
		for _, finding := range findings {
			if strings.HasPrefix(finding, "JUDGE-PII-") {
				entities++
			}
		}
	}
	if entities < minEntities {
		return "", false
	}
	return fmt.Sprintf("tool=%s severity=%s entities=%d", tool, severity, entities), true
}

// buildVerdict converts rule findings into a ToolInspectVerdict.
func buildVerdict(ruleFindings []RuleFinding, direction string) *ToolInspectVerdict {
	return buildVerdictWithConfig(ruleFindings, direction, nil, "", false)
}

// buildVerdict maps the findings with the levels of the connector the hook
// request authenticated as (one threshold model). Under the Secure Client
// integration content keeps the global posture levels, as before.
func (a *APIServer) buildVerdict(ctx context.Context, ruleFindings []RuleFinding, direction string, confirmable bool) *ToolInspectVerdict {
	cfg := (*config.Config)(nil)
	if a != nil {
		cfg = a.decisionConfig(ctx)
	}
	connector := profileRequestConnector(ctx)
	if cfg != nil && cfg.SecureClientIntegration() {
		connector = ""
	}
	return buildVerdictWithConfig(ruleFindings, direction, cfg, connector, confirmable)
}

func buildVerdictWithConfig(ruleFindings []RuleFinding, direction string, cfg *config.Config, connector string, confirmable bool) *ToolInspectVerdict {
	if len(ruleFindings) == 0 {
		return &ToolInspectVerdict{Action: "allow", Severity: "NONE", Findings: []string{}}
	}

	severity := HighestSeverity(ruleFindings)
	confidence := HighestConfidence(ruleFindings, severity)

	action := guardrailContentActionForFindings(cfg, connector, ruleFindings, confirmable)

	reasons := make([]string, 0, minInt(len(ruleFindings), 5))
	for i, f := range ruleFindings {
		if i >= 5 {
			break
		}
		reasons = append(reasons, f.RuleID+":"+f.Title)
	}

	return &ToolInspectVerdict{
		Action:           action,
		Severity:         severity,
		Confidence:       confidence,
		Reason:           fmt.Sprintf("matched: %s", strings.Join(reasons, ", ")),
		Findings:         FindingStrings(ruleFindings),
		DetailedFindings: ruleFindings,
	}
}
