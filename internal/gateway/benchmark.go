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
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semantic"
)

// DeterministicActionFinding is the value-safe benchmark projection of a
// trusted-action finding. It intentionally excludes evidence, commands,
// arguments, paths, URLs, and the private proof object.
type DeterministicActionFinding struct {
	RuleID                   string
	Severity                 string
	Confidence               float64
	Route                    string
	ContributesToEnforcement bool
	Disposition              string
}

// DeterministicActionEvaluation exposes the production trusted-action
// dispatch outcome to the repository's benchmark command. It is an internal
// module API, not a wire contract. Only value-free parser and decision state
// may be added here: ActionFacts and raw finding evidence are private by
// design and must never be serialized by the benchmark.
type DeterministicActionEvaluation struct {
	Findings                     []DeterministicActionFinding
	RuleIDs                      []string
	Severity                     string
	EnforceableSeverity          string
	Action                       string
	Route                        string
	ParseStatus                  string
	Dialect                      string
	IssueCodes                   []string
	Authoritative                bool
	EnforcementEligible          bool
	DetectionStepMask            uint64
	EnforcementStepMask          uint64
	EnforcementJoinDigests       [guardrail.ToolChainCount]string
	EnforcementOutputJoinDigests [guardrail.ToolChainCount]string
	// ValueJoinDigests is an in-memory, value-free projection used by the
	// stateful benchmark runner. It is never copied into a Prediction.
	ValueJoinDigests    [guardrail.ToolChainCount]guardrail.ToolChainValueJoinDigests
	CELEvaluationStatus string
}

// DeterministicToolResultInput models one already-validated, exact
// invocation/result pair for offline benchmarking. Raw result content remains
// request-scoped and is never copied into DeterministicActionEvaluation.
type DeterministicToolResultInput struct {
	Connector     string
	PreEvent      string
	ResultEvent   string
	SessionID     string
	InvocationID  string
	Outcome       string
	ToolName      string
	ToolArgs      json.RawMessage
	ResultContent string
}

// DeterministicHTTPMessageEvaluation is the value-safe projection returned by
// the real /api/v1/inspect/tool HTTP handler for a message request.
type DeterministicHTTPMessageEvaluation struct {
	RuleIDs      []string
	Severity     string
	Action       string
	Detected     bool
	FindingCount int
	StatusCode   int
}

// DeterministicTextSpan is a byte-aligned, value-free local PII match. A
// normalized-only match is deliberately omitted because its offsets do not
// map safely back to the source text.
type DeterministicTextSpan struct {
	Start  int
	End    int
	RuleID string
}

// EvaluateDeterministicTextSpans uses the same accepted PII candidates as the
// local inspector while exposing only offsets and a stable detector ID.
func EvaluateDeterministicTextSpans(content string) []DeterministicTextSpan {
	generation := snapshotRulePackGeneration("")
	var spans []DeterministicTextSpan
	if generation != nil {
		for _, category := range generation.categories {
			if category.Name != "enterprise-data" {
				continue
			}
			for _, rule := range category.Rules {
				if rule.ToolCallOnly || rule.Pattern == nil || !hasTag(rule.Tags, "pii") {
					continue
				}
				for _, loc := range rule.Pattern.FindAllStringIndex(content, -1) {
					if acceptedRuleMatchAt(rule.ID, content, content[loc[0]:loc[1]], loc[0], loc[1]) {
						spans = appendUniqueDeterministicSpan(
							spans,
							DeterministicTextSpan{Start: loc[0], End: loc[1], RuleID: rule.ID},
						)
					}
				}
			}
		}
	}
	localPatternsMu.RLock()
	patterns := append([]*regexp.Regexp(nil), piiDataRegexes...)
	localPatternsMu.RUnlock()
	for _, pattern := range patterns {
		for _, loc := range pattern.FindAllStringIndex(content, -1) {
			match := content[loc[0]:loc[1]]
			if acceptedLocalPIIMatchAt(content, match, loc[0], loc[1]) {
				spans = appendUniqueDeterministicSpan(
					spans,
					DeterministicTextSpan{Start: loc[0], End: loc[1], RuleID: "local.pii"},
				)
			}
		}
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].Start != spans[j].Start {
			return spans[i].Start < spans[j].Start
		}
		if spans[i].End != spans[j].End {
			return spans[i].End < spans[j].End
		}
		return spans[i].RuleID < spans[j].RuleID
	})
	return spans
}

func appendUniqueDeterministicSpan(spans []DeterministicTextSpan, candidate DeterministicTextSpan) []DeterministicTextSpan {
	for _, span := range spans {
		if span.Start == candidate.Start && span.End == candidate.End {
			return spans
		}
	}
	return append(spans, candidate)
}

// EvaluateDeterministicAction runs the same ActionFacts, typed-CEL,
// owner-local fallback, and proof boundary used by trusted connector actions.
// Payloads are inspected only; this function never executes the action.
func EvaluateDeterministicAction(
	ctx context.Context,
	input actionfacts.Input,
	legacyText string,
	connector string,
	profile string,
) DeterministicActionEvaluation {
	var captured actionfacts.Facts
	var capturedFindings []RuleFinding
	findings := dispatchTrustedAction(ctx, trustedActionRequest{
		Input:              input,
		LegacyText:         legacyText,
		Connector:          connector,
		EnforcementCapable: true,
		record: func(facts actionfacts.Facts, recorded []RuleFinding) {
			captured = facts
			capturedFindings = append([]RuleFinding(nil), recorded...)
		},
	})

	result := DeterministicActionEvaluation{
		Severity:            HighestSeverity(findings),
		EnforceableSeverity: HighestSeverity(enforceableRuleFindings(findings)),
		ParseStatus:         string(captured.Parse.Status),
		Dialect:             string(captured.Parse.Dialect),
		Authoritative:       captured.Authoritative(),
		EnforcementEligible: captured.EnforcementEligible(),
	}
	projection := guardrail.ToolChainProjection{ParseStatus: captured.Parse.Status}
	projectTrustedActionChainSteps(&projection, captured, capturedFindings)
	projection = toolChainProjectionForNamedPosture(profile, projection)
	result.DetectionStepMask = projection.DetectionStepMask
	result.EnforcementStepMask = projection.EnforcementStepMask
	result.EnforcementJoinDigests = projection.EnforcementJoinDigests
	result.EnforcementOutputJoinDigests = projection.EnforcementOutputJoinDigests
	result.ValueJoinDigests = projection.ValueJoinDigests
	result.CELEvaluationStatus = deterministicCELEvaluationStatus(connector, captured)
	for _, issue := range captured.Parse.Issues {
		result.IssueCodes = append(result.IssueCodes, string(issue))
	}
	result.Action = guardrailFallbackActionForProfile(result.EnforceableSeverity, profile)
	if alerts := alertOnlyRuleFindings(findings); len(alerts) > 0 {
		alertAction := guardrailFallbackActionForProfile(HighestSeverity(alerts), profile)
		if alertAction == guardrailActionBlock || alertAction == guardrailActionConfirm {
			alertAction = guardrailActionAlert
		}
		result.Action = strongerGuardrailAction(result.Action, alertAction)
	}

	routes := make(map[string]struct{}, 2)
	ruleIDs := make(map[string]struct{}, len(findings))
	for _, finding := range findings {
		route := "semantic"
		if finding.Evidence != "" {
			route = "fallback"
		}
		routes[route] = struct{}{}
		ruleIDs[finding.RuleID] = struct{}{}
		disposition := "enforceable"
		if !finding.contributesToEnforcement() {
			disposition = "detect_only"
		} else {
			switch finding.disposition {
			case findingDispositionAudit:
				disposition = "audit"
			case findingDispositionAdvisory:
				disposition = "advisory"
			}
		}
		result.Findings = append(result.Findings, DeterministicActionFinding{
			RuleID:                   finding.RuleID,
			Severity:                 finding.Severity,
			Confidence:               finding.Confidence,
			Route:                    route,
			ContributesToEnforcement: finding.contributesToEnforcement(),
			Disposition:              disposition,
		})
	}
	for ruleID := range ruleIDs {
		result.RuleIDs = append(result.RuleIDs, ruleID)
	}
	sort.Strings(result.RuleIDs)
	sort.Strings(result.IssueCodes)
	switch len(routes) {
	case 0:
		result.Route = "none"
	case 1:
		for route := range routes {
			result.Route = route
		}
	default:
		result.Route = "mixed"
	}
	result.Action = strings.ToLower(strings.TrimSpace(result.Action))
	return result
}

// ApplyDeterministicSuccessfulActionResult promotes only result-backed chain
// state that the production lifecycle would attach after an authenticated
// successful terminal event. It is used by the offline stateful benchmark to
// replay a value-safe result proof; raw result content and derived identities
// are never copied into a prediction.
func ApplyDeterministicSuccessfulActionResult(
	evaluation DeterministicActionEvaluation,
	resultProof []byte,
) DeterministicActionEvaluation {
	digest := actionfacts.ExactADCSCertificatePFXResult(resultProof)
	if digest == "" {
		return evaluation
	}
	definition, ok := guardrail.ToolChainDefinitionByID(
		guardrail.ToolChainADCSCertificateRequestThenPFXAuth,
	)
	index, indexOK := guardrail.ToolChainIndexByID(
		guardrail.ToolChainADCSCertificateRequestThenPFXAuth,
	)
	if !ok || !indexOK ||
		evaluation.DetectionStepMask&definition.Step1Bit == 0 ||
		evaluation.EnforcementStepMask&definition.Step1Bit != 0 ||
		evaluation.EnforcementJoinDigests[index] != "" ||
		evaluation.EnforcementOutputJoinDigests[index] != "" ||
		evaluation.ValueJoinDigests[index] != (guardrail.ToolChainValueJoinDigests{}) {
		return evaluation
	}
	projection := guardrail.ToolChainProjection{
		ParseStatus:                  actionfacts.ParseStatus(evaluation.ParseStatus),
		DetectionStepMask:            evaluation.DetectionStepMask,
		EnforcementStepMask:          evaluation.EnforcementStepMask | definition.Step1Bit,
		EnforcementJoinDigests:       evaluation.EnforcementJoinDigests,
		EnforcementOutputJoinDigests: evaluation.EnforcementOutputJoinDigests,
		ValueJoinDigests:             evaluation.ValueJoinDigests,
	}
	projection.EnforcementJoinDigests[index] = digest
	if guardrail.ValidateToolChainProjection(projection) != nil {
		return evaluation
	}
	evaluation.EnforcementStepMask = projection.EnforcementStepMask
	evaluation.EnforcementJoinDigests = projection.EnforcementJoinDigests
	return evaluation
}

// EvaluateDeterministicToolResult is the classifier-only benchmark lens for a
// normalized invocation/result pair. It runs the production source grammar,
// connector-specific result parser, and value-free classifier, but does not
// replace lifecycle integration tests: the normalized Outcome is used to
// construct a connector envelope and durable pending-state/replay behavior is
// tested separately. This adapter never serializes input values.
func EvaluateDeterministicToolResult(
	ctx context.Context,
	input DeterministicToolResultInput,
	profile string,
) (DeterministicActionEvaluation, error) {
	if err := ctx.Err(); err != nil {
		return DeterministicActionEvaluation{}, err
	}
	req, outcome, err := deterministicToolResultRequest(input)
	if err != nil {
		return DeterministicActionEvaluation{}, err
	}
	actionTool := input.ToolName
	if _, projected, ok := exactMCPToolResource(input.ToolName, ""); ok {
		actionTool = projected
	}
	facts := actionfacts.Analyze(actionfacts.Input{
		Tool:        actionTool,
		Args:        append(json.RawMessage(nil), input.ToolArgs...),
		ActiveHome:  "/home/alice",
		DialectHint: actionfacts.DialectPOSIX,
	})
	result := DeterministicActionEvaluation{
		Action:              guardrailActionAllow,
		Route:               "none",
		ParseStatus:         string(facts.Parse.Status),
		Dialect:             string(facts.Parse.Dialect),
		Authoritative:       facts.Authoritative(),
		EnforcementEligible: facts.EnforcementEligible(),
		CELEvaluationStatus: deterministicCELEvaluationStatus(input.Connector, facts),
	}
	for _, issue := range facts.Parse.Issues {
		result.IssueCodes = append(result.IssueCodes, string(issue))
	}
	resultBytes, exact := exactReturnedCredentialResultBytes(req, outcome)
	if !exact {
		sort.Strings(result.IssueCodes)
		return result, nil
	}
	findings := returnedCredentialMaterialFindings(
		actionfacts.ExactReturnedCredentialSource(facts),
		actionfacts.ClassifyReturnedCredentialMaterial(resultBytes),
	)
	if len(findings) == 0 {
		sort.Strings(result.IssueCodes)
		return result, nil
	}
	result.Severity = HighestSeverity(findings)
	result.Route = "semantic"
	for _, finding := range findings {
		result.RuleIDs = append(result.RuleIDs, finding.RuleID)
		result.Findings = append(result.Findings, DeterministicActionFinding{
			RuleID:                   finding.RuleID,
			Severity:                 finding.Severity,
			Confidence:               finding.Confidence,
			Route:                    "semantic",
			ContributesToEnforcement: finding.contributesToEnforcement(),
			Disposition:              "detect_only",
		})
	}
	sort.Strings(result.RuleIDs)
	sort.Strings(result.IssueCodes)
	_ = profile // Result hooks are post-action and remain advisory in every posture.
	return result, nil
}

func deterministicToolResultRequest(
	input DeterministicToolResultInput,
) (agentHookRequest, connector.ToolLifecycleOutcome, error) {
	connectorName := canonicalConnectorRulePackKey(input.Connector)
	if connectorName == "" || strings.TrimSpace(input.SessionID) == "" ||
		strings.TrimSpace(input.InvocationID) == "" || strings.TrimSpace(input.ToolName) == "" ||
		len(input.ToolArgs) == 0 || !json.Valid(input.ToolArgs) {
		return agentHookRequest{}, connector.ToolLifecycleOutcomeUnknown,
			errors.New("invalid deterministic tool-result input")
	}
	var outcome connector.ToolLifecycleOutcome
	switch input.Outcome {
	case "succeeded":
		outcome = connector.ToolLifecycleOutcomeSuccess
	case "failed":
		outcome = connector.ToolLifecycleOutcomeFailure
	case "denied":
		outcome = connector.ToolLifecycleOutcomeDenied
	case "cancelled":
		outcome = connector.ToolLifecycleOutcomeCancelled
	default:
		return agentHookRequest{}, connector.ToolLifecycleOutcomeUnknown,
			fmt.Errorf("unsupported deterministic tool-result outcome %q", input.Outcome)
	}
	validLifecycle := false
	switch connectorName {
	case "claudecode", "codex":
		validLifecycle = input.PreEvent == "PreToolUse" &&
			((outcome == connector.ToolLifecycleOutcomeSuccess && input.ResultEvent == "PostToolUse") ||
				(outcome != connector.ToolLifecycleOutcomeSuccess && input.ResultEvent == "PostToolUseFailure"))
	case "opencode":
		validLifecycle = input.PreEvent == "tool.execute.before" &&
			input.ResultEvent == "tool.execute.after"
	case "amp":
		validLifecycle = input.PreEvent == "tool.call" && input.ResultEvent == "tool.result"
	}
	if !validLifecycle {
		return agentHookRequest{}, connector.ToolLifecycleOutcomeUnknown,
			fmt.Errorf("unsupported deterministic tool-result lifecycle for %q", connectorName)
	}
	var args map[string]interface{}
	decoder := json.NewDecoder(bytes.NewReader(input.ToolArgs))
	decoder.UseNumber()
	if err := decoder.Decode(&args); err != nil || args == nil {
		return agentHookRequest{}, connector.ToolLifecycleOutcomeUnknown,
			errors.New("deterministic tool-result args must be an object")
	}
	payload := map[string]interface{}{
		"hook_event_name": input.ResultEvent,
		"session_id":      input.SessionID,
		"tool_call_id":    input.InvocationID,
		"tool_use_id":     input.InvocationID,
		"tool_name":       input.ToolName,
		"tool_input":      args,
	}
	switch connectorName {
	case "claudecode":
		payload["tool_response"] = input.ResultContent
	case "opencode":
		payload["tool_response"] = map[string]interface{}{
			"output": input.ResultContent,
			"metadata": map[string]interface{}{
				"exit": map[bool]int{true: 0, false: 1}[outcome == connector.ToolLifecycleOutcomeSuccess],
			},
		}
	case "amp":
		payload["tool_response"] = input.ResultContent
		if outcome == connector.ToolLifecycleOutcomeSuccess {
			payload["status"] = "done"
		} else {
			payload["status"] = "error"
			payload["error"] = "tool result did not succeed"
		}
	case "codex":
		payload["tool_response"] = map[string]interface{}{
			"content": []interface{}{map[string]interface{}{
				"type": "text", "text": input.ResultContent,
			}},
			"isError": outcome != connector.ToolLifecycleOutcomeSuccess,
		}
	}
	return agentHookRequest{
		ConnectorName:    connectorName,
		HookEventName:    input.ResultEvent,
		SessionID:        input.SessionID,
		ToolInvocationID: input.InvocationID,
		ToolName:         input.ToolName,
		ToolArgs:         append(json.RawMessage(nil), input.ToolArgs...),
		Payload:          payload,
	}, outcome, nil
}

func deterministicCELEvaluationStatus(connector string, facts actionfacts.Facts) string {
	generation := snapshotRulePackGeneration(connector)
	if generation == nil || len(generation.semanticRules) == 0 {
		return "no_semantic_rules"
	}
	if !facts.Authoritative() {
		return "not_authoritative"
	}
	if _, code := semantic.Project(facts); code != semantic.ProjectionOK {
		return "projection_failed"
	}
	return "evaluated"
}

// ActionForDeterministicSeverity applies the same profile action thresholds as
// the gateway. It exists for sequence scoring after the production chain
// matcher returns a value-free severity.
func ActionForDeterministicSeverity(severity, profile string) string {
	return guardrailFallbackActionForProfile(severity, profile)
}

// EvaluateDeterministicHTTPMessage sends an inert request through the actual
// inspect HTTP decoder, timeout, message scanner, profile mapping, and response
// encoder. No listener is opened and no upstream or LLM client is configured.
func EvaluateDeterministicHTTPMessage(
	ctx context.Context,
	content string,
	direction string,
	connector string,
	rulePackDir string,
) (DeterministicHTTPMessageEvaluation, error) {
	cfg := &config.Config{}
	cfg.Guardrail.Enabled = true
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connector
	cfg.Guardrail.RulePackDir = rulePackDir
	cfg.Guardrail.DetectionStrategy = "regex_only"
	api := &APIServer{scannerCfg: cfg, inspectToolScanTimeout: 5 * time.Second}
	body, err := json.Marshal(ToolInspectRequest{
		Tool:      "message",
		Content:   content,
		Direction: direction,
	})
	if err != nil {
		return DeterministicHTTPMessageEvaluation{}, err
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool", bytes.NewReader(body)).WithContext(ctx)
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(withAuthenticatedInspectConnector(request.Context(), connector))
	recorder := httptest.NewRecorder()
	api.handleInspectTool(recorder, request)
	response := recorder.Result()
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return DeterministicHTTPMessageEvaluation{StatusCode: response.StatusCode}, fmt.Errorf("inspect HTTP status %d", response.StatusCode)
	}
	var verdict ToolInspectVerdict
	decoder := json.NewDecoder(response.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&verdict); err != nil {
		return DeterministicHTTPMessageEvaluation{StatusCode: response.StatusCode}, err
	}
	ruleIDs := make([]string, 0, len(verdict.DetailedFindings))
	for _, finding := range verdict.DetailedFindings {
		if finding.RuleID != "" {
			ruleIDs = append(ruleIDs, finding.RuleID)
		}
	}
	sort.Strings(ruleIDs)
	ruleIDs = compactBenchmarkStrings(ruleIDs)
	return DeterministicHTTPMessageEvaluation{
		RuleIDs:      ruleIDs,
		Severity:     strings.ToUpper(strings.TrimSpace(verdict.Severity)),
		Action:       strings.ToLower(strings.TrimSpace(verdict.Action)),
		Detected:     len(verdict.Findings) > 0,
		FindingCount: len(verdict.DetailedFindings),
		StatusCode:   response.StatusCode,
	}, nil
}

func compactBenchmarkStrings(values []string) []string {
	out := values[:0]
	for _, value := range values {
		if value == "" || len(out) > 0 && out[len(out)-1] == value {
			continue
		}
		out = append(out, value)
	}
	return out
}
