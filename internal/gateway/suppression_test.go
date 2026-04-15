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
	"regexp"
	"testing"
)

func TestStripContentForJudge(t *testing.T) {
	supp := &CompiledSuppressions{
		PreJudgeStrips: []CompiledPreJudgeStrip{
			{
				ID:        "STRIP-SYSTEM-SENDER",
				Pattern:   regexp.MustCompile(`\b(cli|system|bot|admin)\b`),
				AppliesTo: []string{"pii"},
			},
		},
	}

	tests := []struct {
		name      string
		content   string
		judgeType string
		want      string
	}{
		{
			name:      "strip cli from PII judge",
			content:   "Username: cli sent a message",
			judgeType: "pii",
			want:      "Username:  sent a message",
		},
		{
			name:      "no strip for injection judge",
			content:   "Username: cli sent a message",
			judgeType: "injection",
			want:      "Username: cli sent a message",
		},
		{
			name:      "strip multiple metadata tokens",
			content:   "system admin bot said hello",
			judgeType: "pii",
			want:      "   said hello",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := StripContentForJudge(tt.content, tt.judgeType, supp)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFilterJudgeFindings(t *testing.T) {
	supp := &CompiledSuppressions{
		FindingSuppressions: []CompiledFindingSuppression{
			{
				ID:             "SUPP-USERNAME-METADATA",
				FindingPattern: "JUDGE-PII-USER",
				EntityPattern:  regexp.MustCompile(`^(cli|system|bot|admin)$`),
				Reason:         "System metadata",
			},
			{
				ID:             "SUPP-IP-PRIVATE",
				FindingPattern: "JUDGE-PII-IP",
				EntityPattern:  regexp.MustCompile(`^(127\.|10\.|192\.168\.)`),
				Reason:         "Private IP",
			},
			{
				ID:             "SUPP-PHONE-EPOCH",
				FindingPattern: "JUDGE-PII-PHONE",
				EntityPattern:  regexp.MustCompile(`^\d{10}$`),
				Condition:      "is_epoch",
				Reason:         "Unix timestamp",
			},
			{
				ID:             "SUPP-EMAIL-CHATID",
				FindingPattern: "JUDGE-PII-EMAIL",
				EntityPattern:  regexp.MustCompile(`^19:[a-f0-9\-]+@unq\.gbl\.spaces$`),
				Reason:         "Teams chatId",
			},
		},
		ToolSuppressions: []CompiledToolSuppression{
			{
				ToolPattern:      regexp.MustCompile(`^graph_auth_status$`),
				SuppressFindings: []string{"JUDGE-PII-USER"},
				Reason:           "Status tool",
			},
		},
	}

	tests := []struct {
		name           string
		findingIDs     []string
		entities       map[string][]string
		tool           string
		wantSurviving  []string
		wantSuppressed int
	}{
		{
			name:       "suppress Username:cli",
			findingIDs: []string{"JUDGE-PII-USER"},
			entities:   map[string][]string{"JUDGE-PII-USER": {"cli"}},
			tool:       "some_tool",
			wantSurviving:  nil,
			wantSuppressed: 1,
		},
		{
			name:       "keep real username",
			findingIDs: []string{"JUDGE-PII-USER"},
			entities:   map[string][]string{"JUDGE-PII-USER": {"john.doe"}},
			tool:       "some_tool",
			wantSurviving:  []string{"JUDGE-PII-USER"},
			wantSuppressed: 0,
		},
		{
			name:       "suppress private IP",
			findingIDs: []string{"JUDGE-PII-IP"},
			entities:   map[string][]string{"JUDGE-PII-IP": {"127.0.0.1"}},
			tool:       "some_tool",
			wantSurviving:  nil,
			wantSuppressed: 1,
		},
		{
			name:       "keep public IP",
			findingIDs: []string{"JUDGE-PII-IP"},
			entities:   map[string][]string{"JUDGE-PII-IP": {"8.8.8.8"}},
			tool:       "some_tool",
			wantSurviving:  []string{"JUDGE-PII-IP"},
			wantSuppressed: 0,
		},
		{
			name:       "suppress epoch timestamp as phone",
			findingIDs: []string{"JUDGE-PII-PHONE"},
			entities:   map[string][]string{"JUDGE-PII-PHONE": {"1776052031"}},
			tool:       "some_tool",
			wantSurviving:  nil,
			wantSuppressed: 1,
		},
		{
			name:       "keep real phone number",
			findingIDs: []string{"JUDGE-PII-PHONE"},
			entities:   map[string][]string{"JUDGE-PII-PHONE": {"5551234567"}},
			tool:       "some_tool",
			wantSurviving:  []string{"JUDGE-PII-PHONE"},
			wantSuppressed: 0,
		},
		{
			name:       "suppress Teams chatId as email",
			findingIDs: []string{"JUDGE-PII-EMAIL"},
			entities:   map[string][]string{"JUDGE-PII-EMAIL": {"19:f1604ab8-1234-5678-abcd-ef0123456789@unq.gbl.spaces"}},
			tool:       "some_tool",
			wantSurviving:  nil,
			wantSuppressed: 1,
		},
		{
			name:       "tool-level suppression",
			findingIDs: []string{"JUDGE-PII-USER"},
			entities:   map[string][]string{"JUDGE-PII-USER": {"john.doe"}},
			tool:       "graph_auth_status",
			wantSurviving:  nil,
			wantSuppressed: 1,
		},
		{
			name:       "mixed findings — partial suppression",
			findingIDs: []string{"JUDGE-PII-USER", "JUDGE-PII-EMAIL", "JUDGE-PII-SSN"},
			entities: map[string][]string{
				"JUDGE-PII-USER":  {"cli"},
				"JUDGE-PII-EMAIL": {"user@example.com"},
				"JUDGE-PII-SSN":   {"123-45-6789"},
			},
			tool:           "some_tool",
			wantSurviving:  []string{"JUDGE-PII-EMAIL", "JUDGE-PII-SSN"},
			wantSuppressed: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			surviving, suppressed := FilterJudgeFindings(tt.findingIDs, tt.entities, tt.tool, supp)
			if len(surviving) != len(tt.wantSurviving) {
				t.Errorf("surviving: got %v, want %v", surviving, tt.wantSurviving)
			}
			if len(suppressed) != tt.wantSuppressed {
				t.Errorf("suppressed count: got %d, want %d", len(suppressed), tt.wantSuppressed)
			}
		})
	}
}

func TestIsEpochTimestamp(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"1776052031", true},
		{"1000000000", true},
		{"2100000000", true},
		{"999999999", false},
		{"2100000001", false},
		{"5551234567", false},
		{"abc", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isEpochTimestamp(tt.input)
			if got != tt.want {
				t.Errorf("isEpochTimestamp(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestFilterRuleFindings(t *testing.T) {
	supp := &CompiledSuppressions{
		FindingSuppressions: []CompiledFindingSuppression{
			{
				ID:             "SUPP-TEST",
				FindingPattern: "SEC-JWT",
				EntityPattern:  regexp.MustCompile(`^eyJhbGciOiJub25lIn0`),
				Reason:         "Test JWT token",
			},
		},
		ToolSuppressions: []CompiledToolSuppression{
			{
				ToolPattern:      regexp.MustCompile(`^test_tool$`),
				SuppressFindings: []string{"CMD-BASH-C"},
				Reason:           "Expected bash usage in test tool",
			},
		},
	}

	findings := []RuleFinding{
		{RuleID: "SEC-JWT", Title: "JWT token", Severity: "MEDIUM", Evidence: "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0"},
		{RuleID: "CMD-BASH-C", Title: "Shell -c", Severity: "LOW", Evidence: "bash -c echo hello"},
		{RuleID: "SEC-AWS-KEY", Title: "AWS key", Severity: "CRITICAL", Evidence: "AKIAIOSFODNN7EXAMPLE"},
	}

	surviving, suppressed := FilterRuleFindings(findings, "test_tool", supp)
	if len(surviving) != 1 {
		t.Errorf("expected 1 surviving finding, got %d: %v", len(surviving), surviving)
	}
	if len(surviving) > 0 && surviving[0].RuleID != "SEC-AWS-KEY" {
		t.Errorf("expected SEC-AWS-KEY to survive, got %s", surviving[0].RuleID)
	}
	if len(suppressed) != 2 {
		t.Errorf("expected 2 suppressed findings, got %d", len(suppressed))
	}
}
