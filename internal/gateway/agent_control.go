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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const agentControlEvaluationPath = "/api/v1/evaluation"

type agentControlClient struct {
	baseURL    string
	apiKey     string
	agentName  string
	failMode   string
	httpClient *http.Client
}

type agentControlEvaluationRequest struct {
	AgentName string           `json:"agent_name"`
	Step      agentControlStep `json:"step"`
	Stage     string           `json:"stage"`
}

type agentControlStep struct {
	Type    string                 `json:"type"`
	Name    string                 `json:"name"`
	Input   interface{}            `json:"input"`
	Output  interface{}            `json:"output,omitempty"`
	Context map[string]interface{} `json:"context,omitempty"`
}

type agentControlEvaluationResponse struct {
	IsSafe     bool                `json:"is_safe"`
	Confidence float64             `json:"confidence"`
	Reason     string              `json:"reason"`
	Matches    []agentControlMatch `json:"matches"`
	Errors     []agentControlMatch `json:"errors"`
	NonMatches []agentControlMatch `json:"non_matches"`
}

type agentControlMatch struct {
	ControlExecutionID string                      `json:"control_execution_id"`
	ControlID          int                         `json:"control_id"`
	ControlName        string                      `json:"control_name"`
	Action             string                      `json:"action"`
	Result             agentControlEvaluatorResult `json:"result"`
	SteeringContext    *agentControlSteering       `json:"steering_context"`
}

type agentControlEvaluatorResult struct {
	Matched    bool                   `json:"matched"`
	Confidence float64                `json:"confidence"`
	Message    string                 `json:"message"`
	Metadata   map[string]interface{} `json:"metadata"`
	Error      string                 `json:"error"`
}

type agentControlSteering struct {
	Message string `json:"message"`
}

type agentControlDecision struct {
	Enabled         bool    `json:"enabled"`
	Matched         bool    `json:"matched"`
	IsSafe          bool    `json:"is_safe"`
	Action          string  `json:"action,omitempty"`
	ControlID       int     `json:"control_id,omitempty"`
	ControlName     string  `json:"control_name,omitempty"`
	Confidence      float64 `json:"confidence,omitempty"`
	Reason          string  `json:"reason,omitempty"`
	SteeringMessage string  `json:"steering_message,omitempty"`
	MatchCount      int     `json:"match_count,omitempty"`
	ErrorCount      int     `json:"error_count,omitempty"`
	NonMatchCount   int     `json:"non_match_count,omitempty"`
	DurationMS      int64   `json:"duration_ms,omitempty"`
	Error           string  `json:"error,omitempty"`
	FailMode        string  `json:"fail_mode,omitempty"`
	Stage           string  `json:"stage,omitempty"`
	StepType        string  `json:"step_type,omitempty"`
	StepName        string  `json:"step_name,omitempty"`
	AgentName       string  `json:"agent_name,omitempty"`
}

func newAgentControlClient(cfg config.AgentControlConfig, fallbackAgentName string) *agentControlClient {
	if !cfg.Enabled {
		return nil
	}
	baseURL := strings.TrimRight(strings.TrimSpace(cfg.URL), "/")
	if baseURL == "" {
		return nil
	}
	agentName := strings.TrimSpace(cfg.AgentName)
	if agentName == "" {
		agentName = normalizedAgentControlName(fallbackAgentName)
	}
	if agentName == "" {
		agentName = "defenseclaw-agent"
	}
	timeout := time.Duration(cfg.EffectiveTimeoutMS()) * time.Millisecond
	return &agentControlClient{
		baseURL:    baseURL,
		apiKey:     cfg.ResolvedAPIKey(),
		agentName:  agentName,
		failMode:   cfg.EffectiveFailMode(),
		httpClient: &http.Client{Timeout: timeout},
	}
}

func normalizedAgentControlName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == ':', r == '_', r == '-':
			b.WriteRune(r)
		case r == ' ' || r == '/' || r == '.':
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-_:")
	if out == "" {
		return ""
	}
	if len(out) < 10 {
		out = "defenseclaw-" + out
	}
	return out
}

func (c *agentControlClient) evaluate(ctx context.Context, stage string, step agentControlStep) *agentControlDecision {
	if c == nil {
		return nil
	}
	stage = normalizedAgentControlStage(stage)
	step.Type = normalizedAgentControlStepType(step.Type)
	step.Name = strings.TrimSpace(step.Name)
	if step.Name == "" {
		step.Name = step.Type
	}
	if step.Input == nil {
		step.Input = ""
	}
	enrichAgentControlStepContext(ctx, &step)

	start := time.Now()
	payload, err := json.Marshal(agentControlEvaluationRequest{
		AgentName: c.agentName,
		Step:      step,
		Stage:     stage,
	})
	if err != nil {
		return c.errorDecision(stage, step, 0, err)
	}
	endpoint := c.baseURL + agentControlEvaluationPath
	if _, parseErr := url.ParseRequestURI(endpoint); parseErr != nil {
		return c.errorDecision(stage, step, 0, parseErr)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return c.errorDecision(stage, step, time.Since(start), err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return c.errorDecision(stage, step, time.Since(start), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return c.errorDecision(stage, step, time.Since(start),
			fmt.Errorf("agent control status=%d body=%s", resp.StatusCode, redaction.ForSinkReason(string(body))))
	}

	var parsed agentControlEvaluationResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return c.errorDecision(stage, step, time.Since(start), err)
	}
	return c.decisionFromResponse(stage, step, &parsed, time.Since(start))
}

func (c *agentControlClient) decisionFromResponse(stage string, step agentControlStep, resp *agentControlEvaluationResponse, elapsed time.Duration) *agentControlDecision {
	if resp == nil {
		return c.errorDecision(stage, step, elapsed, fmt.Errorf("empty agent control response"))
	}
	decision := &agentControlDecision{
		Enabled:       true,
		IsSafe:        resp.IsSafe,
		Confidence:    resp.Confidence,
		Reason:        redaction.ForSinkReason(resp.Reason),
		MatchCount:    len(resp.Matches),
		ErrorCount:    len(resp.Errors),
		NonMatchCount: len(resp.NonMatches),
		DurationMS:    elapsed.Milliseconds(),
		FailMode:      c.failMode,
		Stage:         stage,
		StepType:      step.Type,
		StepName:      step.Name,
		AgentName:     c.agentName,
	}
	if len(resp.Errors) > 0 {
		decision.Error = redaction.ForSinkReason(resp.Errors[0].Result.Error)
	}

	var selected *agentControlMatch
	for i := range resp.Matches {
		m := &resp.Matches[i]
		if selected == nil || agentControlActionRank(m.Action) > agentControlActionRank(selected.Action) {
			selected = m
		}
	}
	if selected == nil {
		return decision
	}

	decision.Matched = true
	decision.Action = normalizedAgentControlAction(selected.Action)
	decision.ControlID = selected.ControlID
	decision.ControlName = selected.ControlName
	if selected.Result.Confidence > 0 {
		decision.Confidence = selected.Result.Confidence
	}
	if msg := strings.TrimSpace(selected.Result.Message); msg != "" {
		decision.Reason = redaction.ForSinkReason(msg)
	}
	if selected.SteeringContext != nil {
		decision.SteeringMessage = redaction.ForSinkReason(selected.SteeringContext.Message)
		if decision.Reason == "" {
			decision.Reason = decision.SteeringMessage
		}
	}
	return decision
}

func (c *agentControlClient) errorDecision(stage string, step agentControlStep, elapsed time.Duration, err error) *agentControlDecision {
	failMode := "open"
	agentName := ""
	if c != nil {
		failMode = c.failMode
		agentName = c.agentName
	}
	action := "error"
	isSafe := true
	matched := false
	reason := "agent control evaluation failed (fail-open)"
	if failMode == "closed" {
		action = "deny"
		isSafe = false
		matched = true
		reason = "agent control evaluation failed (fail-closed)"
	}
	msg := ""
	if err != nil {
		msg = redaction.ForSinkReason(err.Error())
	}
	return &agentControlDecision{
		Enabled:    true,
		Matched:    matched,
		IsSafe:     isSafe,
		Action:     action,
		Confidence: 1.0,
		Reason:     reason,
		DurationMS: elapsed.Milliseconds(),
		Error:      msg,
		FailMode:   failMode,
		Stage:      stage,
		StepType:   step.Type,
		StepName:   step.Name,
		AgentName:  agentName,
	}
}

func normalizedAgentControlStage(stage string) string {
	if strings.EqualFold(strings.TrimSpace(stage), "post") {
		return "post"
	}
	return "pre"
}

func normalizedAgentControlStepType(t string) string {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "llm":
		return "llm"
	case "tool":
		return "tool"
	default:
		return "tool"
	}
}

func normalizedAgentControlAction(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "deny", "block":
		return "deny"
	case "steer":
		return "steer"
	case "observe":
		return "observe"
	case "error":
		return "error"
	default:
		return ""
	}
}

func agentControlActionRank(action string) int {
	switch normalizedAgentControlAction(action) {
	case "deny":
		return 3
	case "steer":
		return 2
	case "observe":
		return 1
	default:
		return 0
	}
}

func agentControlInputFromRaw(raw json.RawMessage) interface{} {
	if len(raw) == 0 {
		return ""
	}
	var parsed interface{}
	if err := json.Unmarshal(raw, &parsed); err == nil {
		return parsed
	}
	return string(raw)
}

func agentControlRawJSONValue(raw json.RawMessage) interface{} {
	return agentControlInputFromRaw(raw)
}

func enrichAgentControlStepContext(ctx context.Context, step *agentControlStep) {
	if step == nil {
		return
	}
	step.Context = agentControlRuntimeCatalogContext(ctx, step.Name, step.Input, step.Context)
	if step.Context == nil {
		step.Context = map[string]interface{}{}
	}
	agentControlTaskIdentityContext(ctx, step.Context)
	if len(step.Context) == 0 {
		step.Context = nil
	}
}

func agentControlContext(kv map[string]string) map[string]interface{} {
	if len(kv) == 0 {
		return nil
	}
	out := make(map[string]interface{}, len(kv))
	for k, v := range kv {
		if strings.TrimSpace(v) != "" {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func agentControlStepForInspect(req *ToolInspectRequest) (string, agentControlStep) {
	stepType := "tool"
	stage := "pre"
	input := agentControlInputFromRaw(req.Args)
	output := interface{}(nil)
	name := req.Tool
	direction := strings.ToLower(strings.TrimSpace(req.Direction))

	if strings.EqualFold(req.Tool, "message") || req.Content != "" {
		stepType = "llm"
		name = "message"
		if req.Content != "" {
			input = req.Content
		}
		switch direction {
		case "outbound", "completion", "response":
			stage = "post"
			output = req.Content
		default:
			stage = "pre"
		}
	}

	return stage, agentControlStep{
		Type:   stepType,
		Name:   firstNonEmpty(name, stepType),
		Input:  input,
		Output: output,
		Context: agentControlContext(map[string]string{
			"direction":        req.Direction,
			"session_id":       req.SessionID,
			"approval_surface": req.ApprovalSurface,
		}),
	}
}

func agentControlStepForAgentHook(req agentHookRequest) (string, agentControlStep) {
	ctx := agentControlContext(map[string]string{
		"connector":  req.ConnectorName,
		"event":      req.HookEventName,
		"session_id": req.SessionID,
		"turn_id":    req.TurnID,
		"cwd":        req.CWD,
		"agent_id":   req.AgentID,
		"agent_type": req.AgentType,
	})
	switch {
	case isPromptLikeEvent(req.HookEventName):
		return "pre", agentControlStep{
			Type:    "llm",
			Name:    firstNonEmpty(req.ToolName, "message"),
			Input:   req.Content,
			Context: ctx,
		}
	case isResultLikeEvent(req.HookEventName):
		return "post", agentControlStep{
			Type:    "tool",
			Name:    firstNonEmpty(req.ToolName, "tool"),
			Input:   agentControlInputFromRaw(req.ToolArgs),
			Output:  firstNonEmpty(req.Content, payloadString(req.Payload, "tool_result"), payloadString(req.Payload, "result")),
			Context: ctx,
		}
	default:
		return "pre", agentControlStep{
			Type:    "tool",
			Name:    firstNonEmpty(req.ToolName, "tool"),
			Input:   agentControlInputFromRaw(req.ToolArgs),
			Context: ctx,
		}
	}
}

func agentControlStepForLLM(stage, model, input, output string, contextFields map[string]string) agentControlStep {
	step := agentControlStep{
		Type:    "llm",
		Name:    firstNonEmpty(model, "llm"),
		Input:   input,
		Context: agentControlContext(contextFields),
	}
	if normalizedAgentControlStage(stage) == "post" {
		step.Output = output
		if step.Input == "" {
			step.Input = "completion"
		}
	}
	return step
}

func agentControlStepForToolCall(name string, args json.RawMessage, contextFields map[string]string) agentControlStep {
	return agentControlStep{
		Type:    "tool",
		Name:    firstNonEmpty(name, "tool"),
		Input:   agentControlInputFromRaw(args),
		Context: agentControlContext(contextFields),
	}
}

func mergeAgentControlIntoToolVerdict(verdict *ToolInspectVerdict, decision *agentControlDecision) {
	if verdict == nil || decision == nil {
		return
	}
	verdict.AgentControl = decision
	if !decision.Matched {
		return
	}
	verdict.Findings = append(verdict.Findings, agentControlFinding(decision))
	reason := agentControlReason(decision)
	switch decision.Action {
	case "deny":
		verdict.Action = guardrailActionBlock
		if guardrailSeverityRank(verdict.Severity) < severityHigh {
			verdict.Severity = "HIGH"
		}
		if verdict.Confidence < decision.Confidence {
			verdict.Confidence = decision.Confidence
		}
		verdict.Reason = appendVerdictReason(verdict.Reason, reason)
	case "steer":
		if verdict.Action == "" || verdict.Action == guardrailActionAllow {
			verdict.Action = guardrailActionAlert
		}
		if guardrailSeverityRank(verdict.Severity) < severityMedium {
			verdict.Severity = "MEDIUM"
		}
		if verdict.Confidence < decision.Confidence {
			verdict.Confidence = decision.Confidence
		}
		verdict.Reason = appendVerdictReason(verdict.Reason, reason)
	}
}

func mergeAgentControlIntoScanVerdict(verdict *ScanVerdict, decision *agentControlDecision) *ScanVerdict {
	if decision == nil {
		return verdict
	}
	if verdict == nil {
		verdict = allowVerdict("agent-control")
	}
	verdict.AgentControl = decision
	if !decision.Matched {
		return verdict
	}
	if verdict.Scanner == "" {
		verdict.Scanner = "agent-control"
	}
	verdict.ScannerSources = append(verdict.ScannerSources, "agent-control")
	verdict.Findings = append(verdict.Findings, agentControlFinding(decision))
	reason := agentControlReason(decision)
	switch decision.Action {
	case "deny":
		verdict.Action = guardrailActionBlock
		if guardrailSeverityRank(verdict.Severity) < severityHigh {
			verdict.Severity = "HIGH"
		}
		verdict.Reason = appendVerdictReason(verdict.Reason, reason)
	case "steer":
		if verdict.Action == "" || verdict.Action == guardrailActionAllow {
			verdict.Action = guardrailActionAlert
		}
		if guardrailSeverityRank(verdict.Severity) < severityMedium {
			verdict.Severity = "MEDIUM"
		}
		verdict.Reason = appendVerdictReason(verdict.Reason, reason)
	}
	return verdict
}

func agentControlFinding(decision *agentControlDecision) string {
	if decision == nil {
		return "agent-control"
	}
	if decision.ControlID > 0 {
		return fmt.Sprintf("agent-control:%d:%s", decision.ControlID, decision.Action)
	}
	return "agent-control:" + decision.Action
}

func agentControlReason(decision *agentControlDecision) string {
	if decision == nil {
		return ""
	}
	name := strings.TrimSpace(decision.ControlName)
	if name == "" && decision.ControlID > 0 {
		name = fmt.Sprintf("%d", decision.ControlID)
	}
	if name == "" {
		name = "control"
	}
	reason := strings.TrimSpace(decision.Reason)
	if reason == "" {
		reason = strings.TrimSpace(decision.SteeringMessage)
	}
	if reason == "" {
		reason = decision.Action
	}
	return fmt.Sprintf("agent-control=%s action=%s reason=%s", name, decision.Action, reason)
}

func annotateAgentControlSpan(ctx context.Context, decision *agentControlDecision) {
	annotateAgentControlTraceSpan(trace.SpanFromContext(ctx), decision)
}

func annotateAgentControlTraceSpan(span trace.Span, decision *agentControlDecision) {
	if decision == nil || span == nil || !span.IsRecording() {
		return
	}
	span.SetAttributes(agentControlSpanAttributes(decision)...)
}

func agentControlSpanAttributes(decision *agentControlDecision) []attribute.KeyValue {
	if decision == nil {
		return nil
	}
	attrs := []attribute.KeyValue{
		attribute.Bool("agent_control.enabled", decision.Enabled),
		attribute.Bool("agent_control.matched", decision.Matched),
		attribute.Bool("agent_control.is_safe", decision.IsSafe),
		attribute.String("agent_control.action", decision.Action),
		attribute.Float64("agent_control.confidence", decision.Confidence),
		attribute.Int("agent_control.match_count", decision.MatchCount),
		attribute.Int("agent_control.error_count", decision.ErrorCount),
		attribute.Int("agent_control.non_match_count", decision.NonMatchCount),
		attribute.Int64("agent_control.duration_ms", decision.DurationMS),
		attribute.String("agent_control.fail_mode", decision.FailMode),
		attribute.String("agent_control.stage", decision.Stage),
		attribute.String("agent_control.step_type", decision.StepType),
		attribute.String("agent_control.step_name", decision.StepName),
		attribute.String("agent_control.agent_name", decision.AgentName),
	}
	if decision.ControlID > 0 {
		attrs = append(attrs, attribute.Int("agent_control.control_id", decision.ControlID))
	}
	if decision.ControlName != "" {
		attrs = append(attrs, attribute.String("agent_control.control_name", decision.ControlName))
	}
	if decision.Reason != "" {
		attrs = append(attrs, attribute.String("agent_control.reason", decision.Reason))
	}
	if decision.SteeringMessage != "" {
		attrs = append(attrs, attribute.String("agent_control.steering_message", decision.SteeringMessage))
	}
	if decision.Error != "" {
		attrs = append(attrs, attribute.String("agent_control.error", decision.Error))
	}
	return attrs
}

func emitAgentControlPolicyDecision(otel *telemetry.Provider, decision *agentControlDecision) {
	if otel == nil || decision == nil || (!decision.Matched && decision.Error == "") {
		return
	}
	target := firstNonEmpty(decision.ControlName, decision.StepName, "agent-control")
	otel.EmitPolicyDecision("agent-control", firstNonEmpty(decision.Action, "observe"), target, decision.StepType, decision.Reason, map[string]string{
		"control_id": fmt.Sprintf("%d", decision.ControlID),
		"stage":      decision.Stage,
		"step_name":  decision.StepName,
		"agent_name": decision.AgentName,
		"matched":    fmt.Sprintf("%v", decision.Matched),
		"error":      decision.Error,
	})
}
