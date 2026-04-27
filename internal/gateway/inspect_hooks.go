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

	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

const (
	maxInspectContentLen = 256 * 1024 // 256 KiB per field
	inspectScanTimeout   = 5 * time.Second
)

// scanWithTimeout runs ScanAllRules under a context deadline. Returns partial
// results if the deadline fires — the caller should treat a timeout as a
// high-severity finding.
func scanWithTimeout(ctx context.Context, text, toolName string, timeout time.Duration) ([]RuleFinding, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ch := make(chan []RuleFinding, 1)
	go func() {
		ch <- ScanAllRules(text, toolName)
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
	if req.Content == "" {
		a.writeJSON(w, http.StatusOK, &ToolInspectVerdict{Action: "allow", Severity: "NONE", Findings: []string{}})
		return
	}

	fmt.Fprintf(os.Stderr, "[inspect] >>> pre-request content_len=%d model=%s\n",
		len(req.Content), req.Model)

	t0 := time.Now()

	ruleFindings, err := scanWithTimeout(r.Context(), req.Content, "user-request", inspectScanTimeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[inspect] pre-request scan timeout after %s\n", time.Since(t0))
		a.writeJSON(w, http.StatusGatewayTimeout, map[string]string{"error": "scan timeout"})
		return
	}
	verdict := buildVerdict(ruleFindings, "prompt")

	mode := "observe"
	if a.scannerCfg != nil {
		mode = a.scannerCfg.Guardrail.Mode
	}
	if mode == "" {
		mode = "observe"
	}
	verdict.Mode = mode

	elapsed := time.Since(t0)

	fmt.Fprintf(os.Stderr, "[inspect] <<< pre-request action=%s severity=%s mode=%s elapsed=%s reason=%q\n",
		verdict.Action, verdict.Severity, verdict.Mode, elapsed, redaction.Reason(verdict.Reason))

	if verdict.Action == "block" {
		fmt.Fprintf(os.Stderr, "[inspect] BLOCKED pre-request severity=%s reason=%q\n",
			verdict.Severity, redaction.Reason(verdict.Reason))
	}

	auditAction := "inspect-request-" + verdict.Action
	if a.otel != nil {
		elapsedMs := float64(elapsed.Milliseconds())
		tool := a.connectorName() + ":pre-request"
		a.otel.RecordInspectEvaluation(context.Background(), tool, verdict.Action, verdict.Severity)
		a.otel.RecordInspectLatency(context.Background(), tool, elapsedMs)
	}

	requestID := RequestIDFromContext(r.Context())
	auditDetails := fmt.Sprintf("severity=%s elapsed=%s mode=%s model=%s",
		verdict.Severity, elapsed, mode, req.Model)
	if requestID != "" {
		auditDetails += fmt.Sprintf(" request_id=%s", requestID)
	}
	_ = a.logger.LogActionCtx(r.Context(), auditAction, "pre-request", auditDetails)

	reveal := wantsReveal(r)
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
	if req.Content == "" {
		a.writeJSON(w, http.StatusOK, &ToolInspectVerdict{Action: "allow", Severity: "NONE", Findings: []string{}})
		return
	}

	fmt.Fprintf(os.Stderr, "[inspect] >>> post-response content_len=%d model=%s\n",
		len(req.Content), req.Model)

	t0 := time.Now()

	ruleFindings, err := scanWithTimeout(r.Context(), req.Content, "llm-response", inspectScanTimeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[inspect] post-response scan timeout after %s\n", time.Since(t0))
		a.writeJSON(w, http.StatusGatewayTimeout, map[string]string{"error": "scan timeout"})
		return
	}
	verdict := buildVerdict(ruleFindings, "completion")

	mode := "observe"
	if a.scannerCfg != nil {
		mode = a.scannerCfg.Guardrail.Mode
	}
	if mode == "" {
		mode = "observe"
	}
	verdict.Mode = mode

	elapsed := time.Since(t0)

	fmt.Fprintf(os.Stderr, "[inspect] <<< post-response action=%s severity=%s mode=%s elapsed=%s reason=%q\n",
		verdict.Action, verdict.Severity, verdict.Mode, elapsed, redaction.Reason(verdict.Reason))

	if verdict.Action == "block" {
		fmt.Fprintf(os.Stderr, "[inspect] BLOCKED post-response severity=%s reason=%q\n",
			verdict.Severity, redaction.Reason(verdict.Reason))
	}

	auditAction := "inspect-response-" + verdict.Action
	if a.otel != nil {
		elapsedMs := float64(elapsed.Milliseconds())
		tool := a.connectorName() + ":post-response"
		a.otel.RecordInspectEvaluation(context.Background(), tool, verdict.Action, verdict.Severity)
		a.otel.RecordInspectLatency(context.Background(), tool, elapsedMs)
	}

	requestID := RequestIDFromContext(r.Context())
	auditDetails := fmt.Sprintf("severity=%s elapsed=%s mode=%s model=%s",
		verdict.Severity, elapsed, mode, req.Model)
	if requestID != "" {
		auditDetails += fmt.Sprintf(" request_id=%s", requestID)
	}
	_ = a.logger.LogActionCtx(r.Context(), auditAction, "post-response", auditDetails)

	reveal := wantsReveal(r)
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

	outputStr := truncateInspectContent(string(req.Output), maxInspectContentLen)

	fmt.Fprintf(os.Stderr, "[inspect] >>> post-tool tool=%q output_len=%d exit_code=%d\n",
		req.Tool, len(outputStr), req.ExitCode)

	t0 := time.Now()

	ruleFindings, err := scanWithTimeout(r.Context(), outputStr, req.Tool+"-response", inspectScanTimeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[inspect] post-tool scan timeout after %s\n", time.Since(t0))
		a.writeJSON(w, http.StatusGatewayTimeout, map[string]string{"error": "scan timeout"})
		return
	}
	verdict := buildVerdict(ruleFindings, "tool_response")

	mode := "observe"
	if a.scannerCfg != nil {
		mode = a.scannerCfg.Guardrail.Mode
	}
	if mode == "" {
		mode = "observe"
	}
	verdict.Mode = mode

	elapsed := time.Since(t0)

	fmt.Fprintf(os.Stderr, "[inspect] <<< post-tool tool=%q action=%s severity=%s mode=%s elapsed=%s reason=%q\n",
		req.Tool, verdict.Action, verdict.Severity, verdict.Mode, elapsed, redaction.Reason(verdict.Reason))

	if verdict.Action == "block" {
		fmt.Fprintf(os.Stderr, "[inspect] BLOCKED post-tool tool=%q severity=%s reason=%q\n",
			req.Tool, verdict.Severity, redaction.Reason(verdict.Reason))
	}

	auditAction := "inspect-tool-response-" + verdict.Action
	if a.otel != nil {
		elapsedMs := float64(elapsed.Milliseconds())
		tool := a.connectorName() + ":post-tool-" + req.Tool
		a.otel.RecordInspectEvaluation(context.Background(), tool, verdict.Action, verdict.Severity)
		a.otel.RecordInspectLatency(context.Background(), tool, elapsedMs)
	}

	requestID := RequestIDFromContext(r.Context())
	auditDetails := fmt.Sprintf("tool=%s severity=%s elapsed=%s mode=%s exit_code=%d",
		req.Tool, verdict.Severity, elapsed, mode, req.ExitCode)
	if requestID != "" {
		auditDetails += fmt.Sprintf(" request_id=%s", requestID)
	}
	_ = a.logger.LogActionCtx(r.Context(), auditAction, req.Tool, auditDetails)

	reveal := wantsReveal(r)
	a.writeJSON(w, http.StatusOK, verdict.sanitizeForResponse(reveal))
}

// buildVerdict converts rule findings into a ToolInspectVerdict.
func buildVerdict(ruleFindings []RuleFinding, direction string) *ToolInspectVerdict {
	if len(ruleFindings) == 0 {
		return &ToolInspectVerdict{Action: "allow", Severity: "NONE", Findings: []string{}}
	}

	severity := HighestSeverity(ruleFindings)
	confidence := HighestConfidence(ruleFindings, severity)

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

	return &ToolInspectVerdict{
		Action:           action,
		Severity:         severity,
		Confidence:       confidence,
		Reason:           fmt.Sprintf("matched: %s", strings.Join(reasons, ", ")),
		Findings:         FindingStrings(ruleFindings),
		DetailedFindings: ruleFindings,
	}
}
