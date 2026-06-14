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

// TestAxesForRuleID_CoversRealScannerRules pins the rule IDs that the
// Go regex pack, the Python plugin scanner, ClawShield, and the LLM
// judges ACTUALLY emit (verified against policies/guardrail/**,
// cli/defenseclaw/scanner/plugin_scanner/rules.py,
// internal/scanner/clawshield_pii.go and the judge YAMLs). A
// regression here means findings from that producer land in
// scan_findings with data_axis=NULL and the correlator never fires on
// them. Use real emitted IDs only — do NOT add hypothetical bare IDs
// like "PII-SSN" or "CRED-AWS" that no producer outputs.
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
		// Go regex secret pack (SEC-* via prefix)
		"SEC-AWS-KEY":    {AxisSensitiveAccess},
		"SEC-GITHUB-PAT": {AxisSensitiveAccess},
		// Plugin scanner credential paths (CRED-* via prefix)
		"CRED-OPENCLAW-DIR": {AxisSensitiveAccess},
		"CRED-OPENCLAW-ENV": {AxisSensitiveAccess},
		// ClawShield PII detector (CS-PII-* via prefix)
		"CS-PII-SSN":   {AxisSensitiveAccess},
		"CS-PII-EMAIL": {AxisSensitiveAccess},
		// Structured-payload secrets (JSON-SEC-* via prefix)
		"JSON-SEC-AWS": {AxisSensitiveAccess},
		// Cognitive / agent-identity tampering (COG-* via prefix)
		"COG-SOUL":      {AxisSensitiveAccess},
		"COG-CLAUDE-MD": {AxisSensitiveAccess},
		// LLM judge finding IDs
		"JUDGE-PII-SSN":        {AxisSensitiveAccess},
		"JUDGE-EXFIL-FILE":     {AxisSensitiveAccess},
		"JUDGE-EXFIL-CHANNEL":  {AxisEgressExternal},
		"JUDGE-INJ-INSTRUCT":   {AxisIngressUntrusted},
		"JUDGE-TOOL-INJ-EXFIL": {AxisSensitiveAccess, AxisEgressExternal},
		// Command rules that open an egress channel
		"CMD-CURL-UPLOAD": {AxisEgressExternal},
		"CMD-ENV-DUMP":    {AxisSensitiveAccess},
		// Cloud metadata C2 endpoints (dual axis)
		"C2-METADATA-AWS": {AxisSensitiveAccess, AxisEgressExternal},
		// SRC-* network members
		"SRC-FETCH":    {AxisEgressExternal},
		"SRC-ENV-READ": {AxisSensitiveAccess},
	}
	for ruleID, want := range cases {
		got := AxesForRuleID(ruleID)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("AxesForRuleID(%q) = %v, want %v", ruleID, got, want)
		}
	}
}

// TestJudgeDestructiveHasNoAxis pins the one tool-injection judge
// category that must NOT carry a trifecta axis — destructive commands
// flow through the capability path (DESTRUCTIVE-FLOW), not the
// ingress/sensitive/egress axes.
func TestJudgeDestructiveHasNoAxis(t *testing.T) {
	if got := AxesForRuleID("JUDGE-TOOL-INJ-DESTRUCT"); len(got) != 0 {
		t.Errorf("AxesForRuleID(JUDGE-TOOL-INJ-DESTRUCT) = %v, want no axis", got)
	}
}

// TestAxesForFinding_Fallbacks verifies the multi-signal entrypoint:
// rule_id first, then judge category, then literal axis tags.
func TestAxesForFinding_Fallbacks(t *testing.T) {
	// 1. rule_id wins.
	if got := AxesForFinding("CS-PII-SSN", "", nil); !reflect.DeepEqual(got, []DataAxis{AxisSensitiveAccess}) {
		t.Errorf("rule_id path = %v, want [sensitive_access]", got)
	}
	// 2. category fallback (bare judge category, no rule_id).
	if got := AxesForFinding("", "Exfiltration Channel", nil); !reflect.DeepEqual(got, []DataAxis{AxisEgressExternal}) {
		t.Errorf("category path = %v, want [egress_external]", got)
	}
	// 3. literal axis tags fallback.
	got := AxesForFinding("", "", []string{"secret", "egress_external", "ingress_untrusted"})
	want := []DataAxis{AxisEgressExternal, AxisIngressUntrusted}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("tags path = %v, want %v", got, want)
	}
	// 4. nothing matches.
	if got := AxesForFinding("TOTALLY-UNKNOWN", "not-a-category", []string{"misc"}); got != nil {
		t.Errorf("no-match path = %v, want nil", got)
	}
}

// TestCapabilityForRuleID_ProducerCoverage pins the rule IDs whose
// matched behaviour exercises a tool capability. Without these the
// DESTRUCTIVE-FLOW correlator pattern can never fire
// on regex/plugin findings (which carry no tool name).
func TestCapabilityForRuleID_ProducerCoverage(t *testing.T) {
	cases := map[string]ToolCapabilityClass{
		// Shell / code execution
		"CMD-REVSHELL-BASH": CapExecShell,
		"CMD-REVSHELL-NC":   CapExecShell,
		"CMD-RM-RF":         CapExecShell,
		"CMD-BASH-C":        CapExecShell,
		"CMD-SUDO":          CapExecShell,
		"SRC-EXEC":          CapExecShell,
		"SRC-CHILD-PROC":    CapExecShell,
		"SRC-EVAL":          CapExecShell,
		// Network fetch
		"CMD-CURL-UPLOAD": CapNetworkFetch,
		"SRC-FETCH":       CapNetworkFetch,
		// Filesystem write
		"SRC-FS-WRITE": CapWriteFS,
		// No capability for a bare secret / injection finding
		"SEC-AWS-KEY":    CapUnknown,
		"INJ-IGNORE-ALL": CapUnknown,
		"COG-SOUL":       CapUnknown,
	}
	for ruleID, want := range cases {
		if got := CapabilityForRuleID(ruleID); got != want {
			t.Errorf("CapabilityForRuleID(%q) = %q, want %q", ruleID, got, want)
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
