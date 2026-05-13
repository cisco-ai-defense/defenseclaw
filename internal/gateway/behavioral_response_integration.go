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
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/behavioralrisk"
	"github.com/defenseclaw/defenseclaw/internal/responseprotection"
)

const (
	behavioralRiskEnabledEnv        = "DEFENSECLAW_BEHAVIORAL_RISK_ENABLE"
	behavioralRiskActionEnv         = "DEFENSECLAW_BEHAVIORAL_RISK_ACTION"
	behavioralRiskBaselineRPMEnv    = "DEFENSECLAW_BEHAVIORAL_BASELINE_RPM"
	responseProtectionEnabledEnv    = "DEFENSECLAW_RESPONSE_PROTECTION_ENABLE"
	responseProtectionFieldsEnv     = "DEFENSECLAW_RESPONSE_PROTECTION_FIELDS"
	responseProtectionMaxRowsEnv    = "DEFENSECLAW_RESPONSE_PROTECTION_MAX_ROWS"
	responseProtectionMaxBytesEnv   = "DEFENSECLAW_RESPONSE_PROTECTION_MAX_BYTES"
	responseProtectionCanaryRateEnv = "DEFENSECLAW_RESPONSE_PROTECTION_CANARY_RATE"
)

// ResponseProtectionEvidence is returned when a post-tool response is masked,
// truncated, or canary-enriched before it is returned to the agent.
type ResponseProtectionEvidence struct {
	Truncated      bool     `json:"truncated"`
	FieldsMasked   []string `json:"fields_masked,omitempty"`
	CanaryInjected bool     `json:"canary_injected,omitempty"`
	RowsReturned   int      `json:"rows_returned,omitempty"`
	BytesReturned  int      `json:"bytes_returned"`
}

var (
	behavioralAnalyzerMu sync.Mutex
	behavioralAnalyzer   *behavioralrisk.Analyzer
)

func applyBehavioralRiskToToolVerdict(ctx context.Context, req *ToolInspectRequest, verdict *ToolInspectVerdict) *ToolInspectVerdict {
	if req == nil || !envFlagLocal(behavioralRiskEnabledEnv) {
		return verdict
	}
	if verdict == nil {
		verdict = &ToolInspectVerdict{Action: guardrailActionAllow, Severity: "NONE", Findings: []string{}}
	}
	id := AgentIdentityFromContext(ctx)
	agentID := firstNonEmpty(id.AgentID, "unknown-agent")
	resourceID, domain := behavioralResourceForTool(req.Tool, string(req.Args))
	result := behavioralRiskAnalyzer().Analyze(ctx, behavioralrisk.Event{
		AgentID:    agentID,
		TaskID:     id.TaskID,
		ResourceID: resourceID,
		Domain:     domain,
		Operation:  req.Tool + " " + string(req.Args),
		Timestamp:  time.Now().UTC(),
	})
	if !result.ShouldAlert && !result.ShouldSuspend {
		return verdict
	}
	finding := fmt.Sprintf("behavioral:risk:%d", result.Score)
	verdict.Findings = append(verdict.Findings, finding)
	verdict.Reason = appendVerdictReason(verdict.Reason, result.Reason)
	if result.ShouldSuspend && strings.EqualFold(strings.TrimSpace(os.Getenv(behavioralRiskActionEnv)), "block") {
		verdict.Action = guardrailActionBlock
		verdict.Severity = maxSeverity(verdict.Severity, "HIGH")
		return verdict
	}
	if actionRank(verdict.Action) < actionRank(guardrailActionAlert) {
		verdict.Action = guardrailActionAlert
	}
	verdict.Severity = maxSeverity(verdict.Severity, "MEDIUM")
	return verdict
}

func behavioralRiskAnalyzer() *behavioralrisk.Analyzer {
	behavioralAnalyzerMu.Lock()
	defer behavioralAnalyzerMu.Unlock()
	if behavioralAnalyzer != nil {
		return behavioralAnalyzer
	}
	baseline := floatFromEnv(behavioralRiskBaselineRPMEnv, behavioralrisk.DefaultBaselineRPM)
	behavioralAnalyzer = behavioralrisk.NewAnalyzer(behavioralrisk.StaticBaseline{DefaultRPM: baseline})
	return behavioralAnalyzer
}

func protectToolResponseForAgent(ctx context.Context, req *ToolResponseInspectRequest) *ResponseProtectionEvidence {
	if req == nil || !envFlagLocal(responseProtectionEnabledEnv) || len(req.Output) == 0 {
		return nil
	}
	cfg := responseProtectionConfigFromEnv()
	id := AgentIdentityFromContext(ctx)
	result := responseprotection.New(cfg).Mask(req.Output, firstNonEmpty(id.AgentID, "unknown-agent"))
	if len(result.Body) > 0 {
		req.Output = json.RawMessage(result.Body)
	}
	if !result.Truncated && !result.CanaryInjected && len(result.FieldsMasked) == 0 {
		return nil
	}
	return &ResponseProtectionEvidence{
		Truncated:      result.Truncated,
		FieldsMasked:   append([]string(nil), result.FieldsMasked...),
		CanaryInjected: result.CanaryInjected,
		RowsReturned:   result.RowsReturned,
		BytesReturned:  result.BytesReturned,
	}
}

func attachResponseProtectionToVerdict(verdict *ToolInspectVerdict, evidence *ResponseProtectionEvidence, protectedOutput json.RawMessage) {
	if verdict == nil || evidence == nil {
		return
	}
	verdict.ResponseProtection = evidence
	if len(protectedOutput) > 0 {
		verdict.ProtectedOutput = protectedOutput
	}
	if len(evidence.FieldsMasked) > 0 {
		verdict.Findings = append(verdict.Findings, "response-protection:masked")
		verdict.Reason = appendVerdictReason(verdict.Reason, "response protection masked fields: "+strings.Join(evidence.FieldsMasked, ","))
	}
	if evidence.Truncated {
		verdict.Findings = append(verdict.Findings, "response-protection:truncated")
		verdict.Reason = appendVerdictReason(verdict.Reason, "response protection truncated tool output")
	}
	if evidence.CanaryInjected {
		verdict.Findings = append(verdict.Findings, "response-protection:canary")
	}
}

func responseProtectionConfigFromEnv() responseprotection.Config {
	cfg := responseprotection.DefaultConfig()
	if fields := strings.TrimSpace(os.Getenv(responseProtectionFieldsEnv)); fields != "" {
		cfg.PIIFields = splitCSV(fields)
	}
	cfg.MaxRows = intFromEnv(responseProtectionMaxRowsEnv, cfg.MaxRows)
	cfg.MaxBytes = intFromEnv(responseProtectionMaxBytesEnv, cfg.MaxBytes)
	cfg.CanaryRate = floatFromEnv(responseProtectionCanaryRateEnv, cfg.CanaryRate)
	return cfg
}

func behavioralResourceForTool(tool, args string) (string, string) {
	lower := strings.ToLower(args)
	if strings.Contains(lower, "customer") || strings.Contains(lower, "email") || strings.Contains(lower, "ssn") {
		return "database:customers", "customer_pii"
	}
	if strings.Contains(lower, "finance") || strings.Contains(lower, "salary") || strings.Contains(lower, "revenue") {
		return "database:financials", "finance"
	}
	if strings.Contains(lower, "employee") || strings.Contains(lower, "people") {
		return "database:employees", "people"
	}
	lt := strings.ToLower(tool)
	if strings.Contains(lt, "http") || strings.Contains(lt, "fetch") || strings.Contains(lt, "api") {
		return "api:unknown", "internal"
	}
	if strings.Contains(lt, "file") {
		return "file:unknown", "internal"
	}
	return "tool:" + strings.TrimSpace(tool), "internal"
}

func maxSeverity(a, b string) string {
	if guardrailSeverityRank(b) > guardrailSeverityRank(a) {
		return b
	}
	if strings.TrimSpace(a) == "" {
		return b
	}
	return a
}

func envFlagLocal(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func intFromEnv(name string, fallback int) int {
	if raw := strings.TrimSpace(os.Getenv(name)); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil {
			return v
		}
	}
	return fallback
}

func floatFromEnv(name string, fallback float64) float64 {
	if raw := strings.TrimSpace(os.Getenv(name)); raw != "" {
		if v, err := strconv.ParseFloat(raw, 64); err == nil {
			return v
		}
	}
	return fallback
}

func splitCSV(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
