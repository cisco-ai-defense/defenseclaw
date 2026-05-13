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

package guardrail

import (
	"reflect"
	"testing"
)

func TestAxesForRuleID_KnownMappings(t *testing.T) {
	cases := []struct {
		ruleID string
		want   []DataAxis
	}{
		{"CRED-AWS-FILE", []DataAxis{AxisSensitiveAccess}},
		{"C2-WEBHOOK-SITE", []DataAxis{AxisEgressExternal}},
		{"INJ-IGNORE-ALL", []DataAxis{AxisIngressUntrusted}},
		{"SEC-SLACK-WEBHOOK", []DataAxis{AxisSensitiveAccess, AxisEgressExternal}},
		{"SSRF-AWS-META", []DataAxis{AxisSensitiveAccess, AxisEgressExternal}},
	}
	for _, c := range cases {
		got := AxesForRuleID(c.ruleID)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("AxesForRuleID(%q) = %v, want %v", c.ruleID, got, c.want)
		}
	}
}

func TestAxesForRuleID_PrefixFallback(t *testing.T) {
	if axes := AxesForRuleID("SEC-NEW-PROVIDER"); !reflect.DeepEqual(axes, []DataAxis{AxisSensitiveAccess}) {
		t.Errorf("SEC-* fallback = %v, want [sensitive_access]", axes)
	}
	if axes := AxesForRuleID("C2-FUTURE-DOMAIN"); !reflect.DeepEqual(axes, []DataAxis{AxisEgressExternal}) {
		t.Errorf("C2-* fallback = %v, want [egress_external]", axes)
	}
	if axes := AxesForRuleID("INJ-NEW-TECHNIQUE"); !reflect.DeepEqual(axes, []DataAxis{AxisIngressUntrusted}) {
		t.Errorf("INJ-* fallback = %v, want [ingress_untrusted]", axes)
	}
}

func TestAxesForRuleID_UnknownReturnsNil(t *testing.T) {
	if axes := AxesForRuleID("TOTALLY-UNKNOWN"); axes != nil {
		t.Errorf("unknown rule should return nil, got %v", axes)
	}
}

// TestAxesForRuleID_CoversRealScannerRules pins the rule families the
// Python plugin/skill/mcp scanners actually emit. A regression here
// means new findings will land in scan_findings with data_axis=NULL
// and the correlator will never fire on those families.
func TestAxesForRuleID_CoversRealScannerRules(t *testing.T) {
	cases := map[string][]DataAxis{
		// Plugin scanner meta-findings
		"META-REMOTE-CODE-EXEC": {AxisIngressUntrusted},
		"META-ENV-EXFIL":        {AxisSensitiveAccess, AxisEgressExternal},
		// Gateway rule family
		"GW-ENV-WRITE": {AxisSensitiveAccess},
		"GW-ENV-READ":  {AxisSensitiveAccess},
		// SSRF family
		"SSRF-GCP-META":      {AxisSensitiveAccess, AxisEgressExternal},
		"SSRF-INTERNAL-HOST": {AxisEgressExternal},
		"SSRF-PRIVATE-IP":    {AxisEgressExternal},
		// PII + credential families
		"PII-SSN":  {AxisSensitiveAccess},
		"CRED-AWS": {AxisSensitiveAccess},
	}
	for ruleID, want := range cases {
		got := AxesForRuleID(ruleID)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("AxesForRuleID(%q) = %v, want %v", ruleID, got, want)
		}
	}
}

func TestAxesForJudgeCategory(t *testing.T) {
	cases := []struct {
		judge, category string
		want            []DataAxis
	}{
		{"injection", "Instruction Manipulation", []DataAxis{AxisIngressUntrusted}},
		{"exfil", "Sensitive File Access", []DataAxis{AxisSensitiveAccess}},
		{"exfil", "Exfiltration Channel", []DataAxis{AxisEgressExternal}},
		{"tool-injection", "Data Exfiltration", []DataAxis{AxisSensitiveAccess, AxisEgressExternal}},
		{"pii", "Social Security Number", []DataAxis{AxisSensitiveAccess}},
	}
	for _, c := range cases {
		got := AxesForJudgeCategory(c.judge, c.category)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("AxesForJudgeCategory(%q, %q) = %v, want %v", c.judge, c.category, got, c.want)
		}
	}
}

func TestAxesForJudgeCategory_CaseInsensitive(t *testing.T) {
	a := AxesForJudgeCategory("INJECTION", "instruction manipulation")
	b := AxesForJudgeCategory("injection", "Instruction Manipulation")
	if !reflect.DeepEqual(a, b) {
		t.Errorf("case-insensitive lookup inconsistent: %v vs %v", a, b)
	}
}

func TestAxesToStrings(t *testing.T) {
	got := AxesToStrings([]DataAxis{AxisIngressUntrusted, AxisEgressExternal})
	want := []string{"ingress_untrusted", "egress_external"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("AxesToStrings = %v, want %v", got, want)
	}
}
