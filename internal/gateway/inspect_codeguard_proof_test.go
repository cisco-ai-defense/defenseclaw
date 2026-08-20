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
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

func TestInspectCodeGuardProofBoundaryBuiltinAndDetectionOnlyInputs(t *testing.T) {
	api := testAPIServerWithConfig(t, "action")
	rulesDir := t.TempDir()
	custom := `version: 1
rules:
  - id: CG-CUSTOM-001
    severity: critical
    title: Custom regex
    pattern: CUSTOM_ONLY_MATCH
    extensions: [.py]
  - id: CG-EXEC-001
    severity: critical
    title: Reused builtin ID
    pattern: CUSTOM_COLLISION
    extensions: [.py]
`
	if err := os.WriteFile(filepath.Join(rulesDir, "custom.yaml"), []byte(custom), 0o600); err != nil {
		t.Fatal(err)
	}
	api.scannerCfg.Scanners.CodeGuard = rulesDir

	tests := []struct {
		name            string
		args            json.RawMessage
		wantAction      string
		wantRuleID      string
		wantEnforceable bool
	}{
		{
			name:            "complete builtin exact match authorizes",
			args:            json.RawMessage(`{"path":"/tmp/app.py","content":"os.system(cmd)"}`),
			wantAction:      guardrailActionAlert,
			wantRuleID:      "CG-EXEC-001",
			wantEnforceable: true,
		},
		{
			name:            "string encoded complete builtin authorizes",
			args:            json.RawMessage(`"{\"path\":\"/tmp/app.py\",\"content\":\"os.system(cmd)\"}"`),
			wantAction:      guardrailActionAlert,
			wantRuleID:      "CG-EXEC-001",
			wantEnforceable: true,
		},
		{
			name:            "irrelevant duplicate metadata preserves exact proof",
			args:            json.RawMessage(`{"path":"/tmp/app.py","content":"os.system(cmd)","unused":1,"unused":2}`),
			wantAction:      guardrailActionAlert,
			wantRuleID:      "CG-EXEC-001",
			wantEnforceable: true,
		},
		{
			name:            "identical duplicate proof fields preserve exact proof",
			args:            json.RawMessage(`{"path":"/tmp/app.py","path":"/tmp/app.py","content":"os.system(cmd)","content":"os.system(cmd)"}`),
			wantAction:      guardrailActionAlert,
			wantRuleID:      "CG-EXEC-001",
			wantEnforceable: true,
		},
		{
			name:       "custom regex is detection only",
			args:       json.RawMessage(`{"path":"/tmp/app.py","content":"CUSTOM_ONLY_MATCH"}`),
			wantAction: guardrailActionAllow,
			wantRuleID: "CG-CUSTOM-001",
		},
		{
			name:       "custom rule reusing builtin id is detection only",
			args:       json.RawMessage(`{"path":"/tmp/app.py","content":"CUSTOM_COLLISION"}`),
			wantAction: guardrailActionAllow,
			wantRuleID: "CG-EXEC-001",
		},
		{
			name:       "ambiguous write envelope remains visible detection only",
			args:       json.RawMessage(`{"path":"/tmp/app.py","file_path":"/tmp/other.py","content":"os.system(cmd)"}`),
			wantAction: guardrailActionAllow,
			wantRuleID: "CG-EXEC-001",
		},
		{
			name:       "duplicate write field remains visible detection only",
			args:       json.RawMessage(`{"path":"/tmp/app.py","path":"/tmp/other.py","content":"os.system(cmd)"}`),
			wantAction: guardrailActionAllow,
			wantRuleID: "CG-EXEC-001",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verdict := inspectCodeGuardProofTestRequest(t, api, test.args)
			if verdict.Action != test.wantAction {
				t.Fatalf("action = %q, want %q; verdict=%+v", verdict.Action, test.wantAction, verdict)
			}
			var matched *RuleFinding
			for i := range verdict.DetailedFindings {
				if verdict.DetailedFindings[i].RuleID == test.wantRuleID {
					matched = &verdict.DetailedFindings[i]
					break
				}
			}
			if matched == nil {
				t.Fatalf("missing visible %s finding: %+v", test.wantRuleID, verdict.DetailedFindings)
			}
			if matched.contributesToEnforcement() != test.wantEnforceable {
				t.Fatalf("finding enforcement = %t, want %t: %+v", matched.contributesToEnforcement(), test.wantEnforceable, matched)
			}
			if matched.Confidence != 1 {
				t.Fatalf("CodeGuard finding confidence = %v, want binary confidence 1: %+v", matched.Confidence, matched)
			}
			if verdict.Confidence != 1 {
				t.Fatalf("CodeGuard-only verdict confidence = %v, want 1: %+v", verdict.Confidence, verdict)
			}
		})
	}
}

func TestInspectCodeGuardBinaryConfidenceFlowsToTelemetry(t *testing.T) {
	api := testAPIServerWithConfig(t, "action")
	verdict := inspectCodeGuardProofTestRequest(
		t,
		api,
		json.RawMessage(`{"path":"/tmp/app.py","content":"os.system(cmd)"}`),
	)
	if verdict.Confidence != 1 || len(verdict.DetailedFindings) != 1 ||
		verdict.DetailedFindings[0].Confidence != 1 {
		t.Fatalf("CodeGuard binary confidence did not reach verdict/details: %+v", verdict)
	}

	input, ok := api.inspectTraceV8Input(
		t.Context(),
		"write_file",
		"tool_call",
		verdict,
		time.Millisecond,
		hookEvaluationContext{},
	)
	if !ok {
		t.Fatal("CodeGuard-only inspect trace input was rejected")
	}
	confidence, present := input.DefenseClawGuardrailConfidence.Get()
	if !present || confidence != 1 {
		t.Fatalf("CodeGuard telemetry confidence = %v (present=%t), want 1", confidence, present)
	}
}

func TestInspectCodeGuardProofBoundaryAlsoGatesAllowlistedWrites(t *testing.T) {
	api := testAPIServerWithConfig(t, "action")
	rulesDir := t.TempDir()
	custom := `version: 1
rules:
  - id: CG-CUSTOM-001
    severity: critical
    title: Custom regex
    pattern: CUSTOM_ONLY_MATCH
    extensions: [.py]
`
	if err := os.WriteFile(filepath.Join(rulesDir, "custom.yaml"), []byte(custom), 0o600); err != nil {
		t.Fatal(err)
	}
	api.scannerCfg.Scanners.CodeGuard = rulesDir
	if err := enforce.NewPolicyEngine(api.store).AllowToolForConnector("write_file", "", "test allow"); err != nil {
		t.Fatal(err)
	}

	customVerdict := inspectCodeGuardProofTestRequest(
		t,
		api,
		json.RawMessage(`{"path":"/tmp/app.py","content":"CUSTOM_ONLY_MATCH"}`),
	)
	if customVerdict.Action != guardrailActionAllow || len(customVerdict.DetailedFindings) != 1 ||
		customVerdict.DetailedFindings[0].contributesToEnforcement() {
		t.Fatalf("allowlisted custom rule authorized: %+v", customVerdict)
	}

	builtinVerdict := inspectCodeGuardProofTestRequest(
		t,
		api,
		json.RawMessage(`{"path":"/tmp/app.py","content":"os.system(cmd)"}`),
	)
	if builtinVerdict.Action != guardrailActionAlert || len(builtinVerdict.DetailedFindings) != 1 ||
		!builtinVerdict.DetailedFindings[0].contributesToEnforcement() {
		t.Fatalf("allowlisted builtin exact finding lost enforcement: %+v", builtinVerdict)
	}
	if builtinVerdict.Confidence != 1 || builtinVerdict.DetailedFindings[0].Confidence != 1 {
		t.Fatalf("allowlisted CodeGuard confidence is inconsistent: %+v", builtinVerdict)
	}
}

func TestInspectCodeGuardDetectionOnlyCriticalDoesNotHideBuiltinProof(t *testing.T) {
	api := testAPIServerWithConfig(t, "action")
	rulesDir := t.TempDir()
	custom := `version: 1
rules:
  - id: CG-CUSTOM-CRITICAL
    severity: critical
    title: Custom critical regex
    pattern: CUSTOM_AND_BUILTIN
    extensions: [.py]
`
	if err := os.WriteFile(filepath.Join(rulesDir, "custom.yaml"), []byte(custom), 0o600); err != nil {
		t.Fatal(err)
	}
	api.scannerCfg.Scanners.CodeGuard = rulesDir

	verdict := inspectCodeGuardProofTestRequest(
		t,
		api,
		json.RawMessage(`{"path":"/tmp/app.py","content":"CUSTOM_AND_BUILTIN os.system(cmd)"}`),
	)
	if verdict.Action != guardrailActionAlert {
		t.Fatalf("detection-only critical hid enforceable builtin high: %+v", verdict)
	}
	var customFinding, builtinFinding *RuleFinding
	for i := range verdict.DetailedFindings {
		switch verdict.DetailedFindings[i].RuleID {
		case "CG-CUSTOM-CRITICAL":
			customFinding = &verdict.DetailedFindings[i]
		case "CG-EXEC-001":
			builtinFinding = &verdict.DetailedFindings[i]
		}
	}
	if customFinding == nil || customFinding.contributesToEnforcement() ||
		builtinFinding == nil || !builtinFinding.contributesToEnforcement() {
		t.Fatalf("mixed CodeGuard provenance was not preserved: %+v", verdict.DetailedFindings)
	}
}

func TestAggregateCodeGuardSeveritySeparatesVisibleAndEnforceable(t *testing.T) {
	findings := []RuleFinding{
		{
			Severity:    string(scanner.SeverityCritical),
			enforcement: findingEnforcementDetectionOnly,
		},
		{
			Severity:    string(scanner.SeverityHigh),
			enforcement: findingEnforcementAllowed,
		},
		{
			Severity:    "MEDIUM",
			enforcement: findingEnforcementAllowed,
		},
	}
	severity, enforceableSeverity := aggregateCodeGuardSeverity(
		findings,
		"LOW",
		"NONE",
	)
	if severity != "CRITICAL" || enforceableSeverity != "HIGH" {
		t.Fatalf(
			"severity/enforceable = %q/%q, want CRITICAL/HIGH",
			severity,
			enforceableSeverity,
		)
	}

	severity, enforceableSeverity = aggregateCodeGuardSeverity(
		[]RuleFinding{{
			Severity:    string(scanner.SeverityHigh),
			enforcement: findingEnforcementAllowed,
		}},
		"CRITICAL",
		"CRITICAL",
	)
	if severity != "CRITICAL" || enforceableSeverity != "CRITICAL" {
		t.Fatalf(
			"existing critical severity was lowered to %q/%q",
			severity,
			enforceableSeverity,
		)
	}

	severity, enforceableSeverity = aggregateCodeGuardSeverity(
		[]RuleFinding{
			{
				Severity:    string(scanner.SeverityMedium),
				enforcement: findingEnforcementAllowed,
			},
			{
				Severity:    string(scanner.SeverityLow),
				enforcement: findingEnforcementDetectionOnly,
			},
		},
		"NONE",
		"NONE",
	)
	if severity != "MEDIUM" || enforceableSeverity != "MEDIUM" {
		t.Fatalf(
			"medium/low severity aggregation = %q/%q, want MEDIUM/MEDIUM",
			severity,
			enforceableSeverity,
		)
	}
}

func TestCodeGuardRuleFindingsRetainsUntitledCustomRuleAsDetectionOnly(t *testing.T) {
	findings := codeGuardRuleFindings(codeGuardArgsScan{
		findings: []scanner.Finding{{
			RuleID:   "CG-CUSTOM-UNTITLED",
			Severity: scanner.SeverityHigh,
		}},
		complete: true,
	}, true, true)
	if len(findings) != 1 {
		t.Fatalf("untitled custom findings = %+v, want one visible finding", findings)
	}
	if findings[0].Title != "CG-CUSTOM-UNTITLED" {
		t.Fatalf("untitled custom finding title = %q", findings[0].Title)
	}
	if findings[0].contributesToEnforcement() {
		t.Fatalf("untitled custom finding authorized enforcement: %+v", findings[0])
	}
}

func TestHighestInspectConfidenceIncludesCodeGuardFindings(t *testing.T) {
	ruleFindings := []RuleFinding{
		{Severity: "MEDIUM", Confidence: 0.99},
		{Severity: "HIGH", Confidence: 0.61},
	}
	codeGuardFindings := []RuleFinding{
		{Severity: "HIGH", Confidence: 0.87},
		{Severity: "LOW", Confidence: 1},
	}

	if got := highestInspectConfidence(ruleFindings, codeGuardFindings, "HIGH"); got != 0.87 {
		t.Fatalf("confidence = %.2f, want highest HIGH confidence 0.87", got)
	}
	if got := highestInspectConfidence(nil, codeGuardFindings, "HIGH"); got != 0.87 {
		t.Fatalf("CodeGuard-only confidence = %.2f, want 0.87", got)
	}
}

func TestInspectCodeGuardProofCannotBeReplayedFromJSON(t *testing.T) {
	scan := scanner.NewCodeGuardScanner(t.TempDir()).ScanContentWithProvenance(
		"app.py",
		"os.system(cmd)",
	)
	wire, err := json.Marshal(scan.Findings())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(wire)), "proof") ||
		strings.Contains(strings.ToLower(string(wire)), "provenance") ||
		strings.Contains(strings.ToLower(string(wire)), "authoritative") {
		t.Fatalf("CodeGuard proof leaked to public JSON: %s", wire)
	}
	var decoded []scanner.Finding
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatal(err)
	}
	findings := codeGuardRuleFindings(codeGuardArgsScan{
		findings: decoded,
		complete: true,
	}, true, true)
	if len(findings) != 1 || findings[0].contributesToEnforcement() {
		t.Fatalf("JSON/client-controlled finding authorized: %+v", findings)
	}
}

func TestInspectCodeGuardBuiltinProofRequiresTrustedBoundary(t *testing.T) {
	scan := scanner.NewCodeGuardScanner(t.TempDir()).ScanContentWithProvenance(
		"app.py",
		"os.system(cmd)",
	)
	findings := codeGuardRuleFindings(codeGuardArgsScan{
		findings: scan.Findings(),
		complete: scan.Complete(),
	}, false, true)
	if len(findings) != 1 || findings[0].contributesToEnforcement() {
		t.Fatalf("builtin finding outside trusted boundary authorized: %+v", findings)
	}
}

func TestInspectCodeGuardFindingProofIsAbsentFromVerdictJSON(t *testing.T) {
	api := testAPIServerWithConfig(t, "action")
	verdict := inspectCodeGuardProofTestRequest(
		t,
		api,
		json.RawMessage(`{"path":"/tmp/app.py","content":"os.system(cmd)"}`),
	)
	wire, err := json.Marshal(verdict)
	if err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(string(wire))
	for _, forbidden := range []string{"proof", "provenance", "authoritative", "scan_complete", "trusted_boundary"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("private proof field %q leaked to verdict JSON: %s", forbidden, wire)
		}
	}
}

func inspectCodeGuardProofTestRequest(
	t *testing.T,
	api *APIServer,
	args json.RawMessage,
) *ToolInspectVerdict {
	t.Helper()
	req := &ToolInspectRequest{
		Tool: "write_file", Args: args, Direction: "tool_call", Connector: "codex",
	}
	return api.inspectTrustedToolPolicyCtx(t.Context(), req, trustedActionRequest{
		Input:              actionfacts.Input{Tool: req.Tool, Args: args, CWD: "/repo"},
		LegacyText:         string(args),
		Connector:          req.Connector,
		EnforcementCapable: true,
	})
}
