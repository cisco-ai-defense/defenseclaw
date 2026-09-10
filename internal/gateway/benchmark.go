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
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
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
	CELEvaluationStatus          string
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
	result.DetectionStepMask = projection.DetectionStepMask
	result.EnforcementStepMask = projection.EnforcementStepMask
	result.EnforcementJoinDigests = projection.EnforcementJoinDigests
	result.EnforcementOutputJoinDigests = projection.EnforcementOutputJoinDigests
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
