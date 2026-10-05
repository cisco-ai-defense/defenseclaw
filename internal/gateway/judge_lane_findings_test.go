// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
package gateway

import "testing"

// TestJudgeLaneFindingsKeepTheirJudge pins GAP-1886: a judge finding in the
// hook verdict is titled by its category and keeps the severity of the judge
// that reported it. The exfil finding of a prompt the PII judge also flagged
// was stored as "JUDGE-EXFIL-FILE: JUDGE-EXFIL-FILE" with the PII judge's
// CRITICAL, though the exfil judge said HIGH.
func TestJudgeLaneFindingsKeepTheirJudge(t *testing.T) {
	merged := mergeJudgeVerdicts([]*ScanVerdict{
		{Action: "block", Severity: "CRITICAL", Findings: []string{"JUDGE-PII-SSN"}, Scanner: "llm-judge-pii"},
		{Action: "block", Severity: "HIGH", Findings: []string{"JUDGE-EXFIL-FILE"}, Scanner: "llm-judge-exfil"},
	})
	got := mergeWithJudgeVerdict(nil, merged)
	if got.Severity != "CRITICAL" || got.Action != "block" {
		t.Fatalf("verdict = %s/%s, want block/CRITICAL", got.Action, got.Severity)
	}
	want := map[string][2]string{
		"JUDGE-PII-SSN":    {"Social Security Number", "CRITICAL"},
		"JUDGE-EXFIL-FILE": {"Sensitive File Access", "HIGH"},
	}
	if len(got.DetailedFindings) != len(want) {
		t.Fatalf("findings = %+v", got.DetailedFindings)
	}
	for _, f := range got.DetailedFindings {
		if w := want[f.RuleID]; f.Title != w[0] || f.Severity != w[1] {
			t.Errorf("%s = %q/%s, want %q/%s", f.RuleID, f.Title, f.Severity, w[0], w[1])
		}
	}
	// An AI Defense finding keeps its name and the lane's severity.
	aid := mergeWithAIDVerdict(nil, &ScanVerdict{Action: "block", Severity: "HIGH", Findings: []string{"PROMPT_INJECTION"}})
	if f := aid.DetailedFindings[0]; f.Title != "PROMPT_INJECTION" || f.Severity != "HIGH" {
		t.Errorf("AI Defense finding = %+v", f)
	}
}
