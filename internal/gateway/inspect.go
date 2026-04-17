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
	Tool      string          `json:"tool"`
	Args      json.RawMessage `json:"args,omitempty"`
	Content   string          `json:"content,omitempty"`
	Direction string          `json:"direction,omitempty"`
}

// ToolInspectVerdict is the response from the inspect endpoint.
type ToolInspectVerdict struct {
	Action           string        `json:"action"`
	Severity         string        `json:"severity"`
	Confidence       float64       `json:"confidence"`
	Reason           string        `json:"reason"`
	Findings         []string      `json:"findings"`
	DetailedFindings []RuleFinding `json:"detailed_findings,omitempty"`
	Mode             string        `json:"mode"`
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

	ruleFindings := ScanAllRules(argsStr, toolName)

	// CodeGuard: scan file content for write_file/edit_file tools.
	tool := strings.ToLower(toolName)
	isWriteTool := tool == "write_file" || tool == "edit_file"
	var cgFindings []scanner.Finding
	if isWriteTool {
		cgFindings = a.runCodeGuardOnArgs(req)
	}

	if len(ruleFindings) == 0 && len(cgFindings) == 0 {
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

	action := "alert"
	if severity == "HIGH" || severity == "CRITICAL" {
		action = "block"
	}

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

	return &ToolInspectVerdict{
		Action:           action,
		Severity:         severity,
		Confidence:       confidence,
		Reason:           fmt.Sprintf("matched: %s", strings.Join(reasons, ", ")),
		Findings:         findingStrs,
		DetailedFindings: ruleFindings,
	}
}

// runCodeGuardOnArgs extracts path/content from write_file/edit_file args
// and runs CodeGuard content scanning.
func (a *APIServer) runCodeGuardOnArgs(req *ToolInspectRequest) []scanner.Finding {
	var parsed map[string]interface{}
	if err := json.Unmarshal(req.Args, &parsed); err != nil {
		return nil
	}

	filePath, _ := parsed["path"].(string)
	content, _ := parsed["content"].(string)
	if content == "" {
		content, _ = parsed["new_string"].(string)
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

	// Outbound messages get the full scan — tool name "message" for context
	ruleFindings := ScanAllRules(content, "message")

	if len(ruleFindings) == 0 {
		return &ToolInspectVerdict{Action: "allow", Severity: "NONE", Findings: []string{}}
	}

	severity := HighestSeverity(ruleFindings)
	confidence := HighestConfidence(ruleFindings, severity)

	// Outbound messages with any findings default to block —
	// content is about to leave the system boundary.
	action := "block"
	if severity == "LOW" {
		action = "alert"
	}

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

	// Stderr is operator-facing: honor the Reveal flag via the
	// Reveal-aware String/MessageContent helpers. Args are
	// MessageContent-shaped (raw tool inputs, often containing the
	// offending value), Content is exactly an LLM message body.
	fmt.Fprintf(os.Stderr, "[inspect] >>> tool=%q args=%s content_len=%d direction=%s\n",
		req.Tool, redaction.MessageContent(string(req.Args)), len(req.Content), req.Direction)

	t0 := time.Now()

	var verdict *ToolInspectVerdict

	if strings.ToLower(req.Tool) == "message" && (req.Content != "" || req.Direction == "outbound") {
		verdict = a.inspectMessageContent(&req)
	} else {
		verdict = a.inspectToolPolicy(&req)
	}

	mode := "observe"
	if a.scannerCfg != nil {
		mode = a.scannerCfg.Guardrail.Mode
	}
	if mode == "" {
		mode = "observe"
	}
	verdict.Mode = mode

	elapsed := time.Since(t0)

	// verdict.Reason is composed as "matched: <rule-id>:<title>"
	// which is PII-safe by construction (rule metadata only).
	// redaction.Reason is a no-op on it because every token passes
	// the rule-id allow-list — we still route through the helper
	// so any future reason-building logic that embeds literals
	// picks up the scrub automatically.
	fmt.Fprintf(os.Stderr, "[inspect] <<< tool=%q action=%s severity=%s mode=%s confidence=%.2f elapsed=%s reason=%q findings=%v\n",
		req.Tool, verdict.Action, verdict.Severity, verdict.Mode, verdict.Confidence, elapsed,
		redaction.Reason(verdict.Reason), verdict.Findings)

	switch verdict.Action {
	case "block":
		fmt.Fprintf(os.Stderr, "[inspect] BLOCKED tool=%q severity=%s reason=%q\n",
			req.Tool, verdict.Severity, redaction.Reason(verdict.Reason))
	case "alert":
		fmt.Fprintf(os.Stderr, "[inspect] ALERT tool=%q severity=%s reason=%q\n",
			req.Tool, verdict.Severity, redaction.Reason(verdict.Reason))
	}

	var auditAction string
	switch verdict.Action {
	case "block":
		auditAction = "inspect-tool-block"
	case "alert":
		auditAction = "inspect-tool-alert"
	default:
		auditAction = "inspect-tool-allow"
	}
	var traceID string
	if a.otel != nil {
		elapsedMs := float64(elapsed.Milliseconds())
		a.otel.RecordInspectEvaluation(context.Background(), req.Tool, verdict.Action, verdict.Severity)
		a.otel.RecordInspectLatency(context.Background(), req.Tool, elapsedMs)
		a.otel.RecordGuardrailEvaluation(context.Background(), "policy-rules", verdict.Action)
		a.otel.RecordGuardrailLatency(context.Background(), "policy-rules", elapsedMs)
		traceID = a.otel.EmitInspectSpan(context.Background(), req.Tool, verdict.Action, verdict.Severity, elapsedMs)
	}

	requestID := RequestIDFromContext(r.Context())
	auditDetails := fmt.Sprintf("severity=%s confidence=%.2f reason=%s elapsed=%s mode=%s",
		verdict.Severity, verdict.Confidence, verdict.Reason, elapsed, mode)
	if requestID != "" {
		auditDetails += fmt.Sprintf(" request_id=%s", requestID)
	}
	_ = a.logger.LogActionWithCorrelation(auditAction, req.Tool, auditDetails, traceID, requestID)

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
		_ = a.logger.LogActionWithCorrelation("inspect-reveal", req.Tool,
			fmt.Sprintf("severity=%s remote=%s reason=%s",
				verdict.Severity, r.RemoteAddr,
				redaction.ForSinkReason(verdict.Reason)),
			traceID, requestID)
	}
	a.writeJSON(w, http.StatusOK, responseVerdict)
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
