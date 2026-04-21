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
	"testing"
)

func TestNormalizeScanVerdict_Basic(t *testing.T) {
	v := &ScanVerdict{
		Action:   "block",
		Severity: "HIGH",
		Findings: []string{"SEC-AWS-KEY:AWS access key", "CMD-REVSHELL-BASH:Bash reverse shell"},
		Scanner:  "local-pattern",
	}
	nfs := NormalizeScanVerdict(v)
	if len(nfs) != 2 {
		t.Fatalf("expected 2 normalized findings, got %d", len(nfs))
	}

	aws := nfs[0]
	if aws.CanonicalID != "SEC-AWS-KEY" {
		t.Errorf("expected canonical ID SEC-AWS-KEY, got %q", aws.CanonicalID)
	}
	if aws.Category != CatCredentialLeak {
		t.Errorf("expected category %s, got %q", CatCredentialLeak, aws.Category)
	}
	if aws.Source != "local-pattern" {
		t.Errorf("expected source local-pattern, got %q", aws.Source)
	}

	shell := nfs[1]
	if shell.Category != CatDangerousExec {
		t.Errorf("expected category %s, got %q", CatDangerousExec, shell.Category)
	}
}

func TestNormalizeScanVerdict_Nil(t *testing.T) {
	if nfs := NormalizeScanVerdict(nil); nfs != nil {
		t.Errorf("expected nil for nil verdict, got %v", nfs)
	}
	if nfs := NormalizeScanVerdict(&ScanVerdict{}); nfs != nil {
		t.Errorf("expected nil for empty findings, got %v", nfs)
	}
}

func TestNormalizeScanVerdict_JudgeFindings(t *testing.T) {
	v := &ScanVerdict{
		Action:   "block",
		Severity: "HIGH",
		Findings: []string{"JUDGE-INJ-INSTRUCT", "JUDGE-PII-EMAIL"},
		Scanner:  "llm-judge",
	}
	nfs := NormalizeScanVerdict(v)
	if len(nfs) != 2 {
		t.Fatalf("expected 2, got %d", len(nfs))
	}
	if nfs[0].Category != CatPromptInjection {
		t.Errorf("expected %s, got %q", CatPromptInjection, nfs[0].Category)
	}
	if nfs[1].Category != CatPIIExposure {
		t.Errorf("expected %s, got %q", CatPIIExposure, nfs[1].Category)
	}
}

func TestNormalizeScanVerdict_LocalPatternFindings(t *testing.T) {
	v := &ScanVerdict{
		Action:   "block",
		Severity: "HIGH",
		Findings: []string{"pii-data:123-45-6789", "ignore previous instructions"},
		Scanner:  "local-pattern",
	}
	nfs := NormalizeScanVerdict(v)
	if len(nfs) != 2 {
		t.Fatalf("expected 2, got %d", len(nfs))
	}
	if nfs[0].CanonicalID != "LP-PII-DATA" {
		t.Errorf("expected LP-PII-DATA, got %q", nfs[0].CanonicalID)
	}
	if nfs[1].CanonicalID != "LP-INJ-IGNORE" {
		t.Errorf("expected LP-INJ-IGNORE, got %q", nfs[1].CanonicalID)
	}
}

func TestNormalizeScanVerdict_SourceFallback(t *testing.T) {
	v := &ScanVerdict{
		Findings:       []string{"foo"},
		ScannerSources: []string{"local-pattern", "ai-defense"},
	}
	nfs := NormalizeScanVerdict(v)
	if len(nfs) != 1 {
		t.Fatalf("expected 1, got %d", len(nfs))
	}
	if nfs[0].Source != "local-pattern+ai-defense" {
		t.Errorf("expected concatenated source, got %q", nfs[0].Source)
	}
}

func TestNormalizeRuleFindings(t *testing.T) {
	findings := []RuleFinding{
		{RuleID: "SEC-AWS-KEY", Title: "AWS access key", Severity: "CRITICAL", Confidence: 0.95, Tags: []string{"credential"}},
		{RuleID: "TRUST-JAILBREAK", Title: "Jailbreak attempt", Severity: "CRITICAL", Confidence: 0.92, Tags: []string{"prompt-injection"}},
		{RuleID: "C2-NGROK", Title: "ngrok tunnel", Severity: "HIGH", Confidence: 0.85, Tags: []string{"exfiltration", "c2"}},
	}

	nfs := NormalizeRuleFindings(findings, "tool-call-inspect")
	if len(nfs) != 3 {
		t.Fatalf("expected 3, got %d", len(nfs))
	}

	tests := []struct {
		idx         int
		canonicalID string
		category    string
	}{
		{0, "SEC-AWS-KEY", CatCredentialLeak},
		{1, "TRUST-JAILBREAK", CatPromptInjection},
		{2, "C2-NGROK", CatDataExfil},
	}

	for _, tt := range tests {
		nf := nfs[tt.idx]
		if nf.CanonicalID != tt.canonicalID {
			t.Errorf("[%d] expected canonicalID %q, got %q", tt.idx, tt.canonicalID, nf.CanonicalID)
		}
		if nf.Category != tt.category {
			t.Errorf("[%d] expected category %q, got %q", tt.idx, tt.category, nf.Category)
		}
		if nf.Source != "tool-call-inspect" {
			t.Errorf("[%d] expected source tool-call-inspect, got %q", tt.idx, nf.Source)
		}
	}
}

func TestNormalizeSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"CRITICAL", "CRITICAL"},
		{"high", "HIGH"},
		{"Medium", "MEDIUM"},
		{"LOW", "LOW"},
		{"NONE", "NONE"},
		{"CRIT", "CRITICAL"},
		{"MED", "MEDIUM"},
		{"INFO", "LOW"},
		{"INFORMATIONAL", "LOW"},
		{"unknown", "MEDIUM"},
		{"", "MEDIUM"},
	}

	for _, tt := range tests {
		got := normalizeSeverity(tt.input)
		if got != tt.expected {
			t.Errorf("normalizeSeverity(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestCategoryFromTags(t *testing.T) {
	tests := []struct {
		tags     []string
		expected string
	}{
		{[]string{"prompt-injection"}, CatPromptInjection},
		{[]string{"credential"}, CatCredentialLeak},
		{[]string{"execution", "reverse-shell"}, CatDangerousExec},
		{[]string{"exfiltration", "c2"}, CatDataExfil},
		{[]string{"cognitive-tampering"}, CatCognitiveTamper},
		{[]string{"system-file"}, CatSystemFile},
		{[]string{"ssrf"}, CatSSRF},
		{[]string{"misc"}, CatGeneral},
		{nil, CatGeneral},
	}

	for _, tt := range tests {
		got := categoryFromTags(tt.tags)
		if got != tt.expected {
			t.Errorf("categoryFromTags(%v) = %q, want %q", tt.tags, got, tt.expected)
		}
	}
}

func TestCanonicalIDFromRuleID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"SEC-AWS-KEY", "SEC-AWS-KEY"},
		{"CMD-REVSHELL-BASH", "CMD-REVSHELL-BASH"},
		{"JUDGE-INJ-INSTRUCT", "JUDGE-INJ-INSTRUCT"},
		{"JUDGE-PII-EMAIL", "JUDGE-PII-EMAIL"},
		{"pii-data:123-45-6789", "LP-PII-DATA"},
		{"pii-request:social security number", "LP-PII-REQUEST"},
		{"ignore previous instructions", "LP-INJ-IGNORE"},
		{"jailbreak", "LP-INJ-JAILBREAK"},
		{"sk-ant-something", "LP-SECRET-MATCH"},
		{"/etc/passwd", "LP-SYSTEM-FILE"},
		{"base64 --decode", "LP-EXFIL"},
	}

	for _, tt := range tests {
		got := canonicalIDFromRuleID(tt.input)
		if got != tt.expected {
			t.Errorf("canonicalIDFromRuleID(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}
