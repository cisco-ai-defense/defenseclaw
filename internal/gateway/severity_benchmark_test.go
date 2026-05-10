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
)

type benchCase struct {
	ID                       string   `json:"id"`
	Direction                string   `json:"direction"`
	Content                  string   `json:"content"`
	ExpectedSeverityAtLeast  string   `json:"expected_severity_at_least,omitempty"`
	ExpectedAction           string   `json:"expected_action,omitempty"`
	ForbiddenSeverityAtLeast string   `json:"forbidden_severity_at_least,omitempty"`
	MustIncludeFindingsSub   []string `json:"must_include_findings_substr,omitempty"`
	NoteLLMRequired          bool     `json:"note_llm_required,omitempty"`
	AdversarialGoal          string   `json:"adversarial_goal,omitempty"`
}

type benchFile struct {
	Cases []benchCase `json:"cases"`
}

// benchmarkSyntheticRSAPrivateKeyPEM returns a minimal PEM-shaped string that
// triggers SEC-PRIVKEY without storing a contiguous "BEGIN … PRIVATE KEY"
// marker in labels.json (avoids GitHub secret scanning alerts on fixtures).
func benchmarkSyntheticRSAPrivateKeyPEM() string {
	return "-----BEGIN " + "RSA " + "PRIVATE KEY-----\n" +
		"MIIEpAIBAAKCAQEA\n" +
		"-----END " + "RSA " + "PRIVATE KEY-----"
}

// TestSeverityBenchmark runs labeled fixtures through scanLocalPatterns
// and asserts the severity/action contracts. Cases flagged with
// note_llm_required are skipped unless GUARDRAIL_BENCHMARK_LLM=1 —
// those rely on the LLM judge and cannot be validated by regex alone.
//
// Failure of a case here is a regression in either the rule pack or
// the severity rubric. Failures are reported as t.Errorf (not Fatal)
// so a single run reports every regression in one pass.
func TestSeverityBenchmark(t *testing.T) {
	path := filepath.Join("testdata", "severity_benchmark", "labels.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read benchmark labels: %v", err)
	}
	var file benchFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("parse benchmark labels: %v", err)
	}
	if len(file.Cases) == 0 {
		t.Fatal("benchmark labels empty")
	}

	for i := range file.Cases {
		if file.Cases[i].ID == "critical/private-key-in-completion" {
			file.Cases[i].Content = benchmarkSyntheticRSAPrivateKeyPEM()
		}
	}

	runLLMCases := os.Getenv("GUARDRAIL_BENCHMARK_LLM") == "1"

	// Tally per-tier pass/fail for a summary line.
	stats := map[string]struct{ pass, fail int }{}
	recordResult := func(tier string, passed bool) {
		s := stats[tier]
		if passed {
			s.pass++
		} else {
			s.fail++
		}
		stats[tier] = s
	}

	for _, c := range file.Cases {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			if c.NoteLLMRequired && !runLLMCases {
				t.Skipf("LLM-gated case; set GUARDRAIL_BENCHMARK_LLM=1 to run")
			}
			tier := strings.SplitN(c.ID, "/", 2)[0]

			verdict := scanLocalPatterns(c.Direction, c.Content)
			if verdict == nil {
				t.Fatal("scanLocalPatterns returned nil")
			}

			passed := true

			if c.ExpectedSeverityAtLeast != "" {
				gotRank := severityRank[verdict.Severity]
				wantRank := severityRank[c.ExpectedSeverityAtLeast]
				if gotRank < wantRank {
					t.Errorf("severity=%s, want >= %s (findings=%v reason=%q)",
						verdict.Severity, c.ExpectedSeverityAtLeast, verdict.Findings, verdict.Reason)
					passed = false
				}
			}
			if c.ForbiddenSeverityAtLeast != "" {
				gotRank := severityRank[verdict.Severity]
				forbiddenRank := severityRank[c.ForbiddenSeverityAtLeast]
				if gotRank >= forbiddenRank {
					t.Errorf("severity=%s (>= forbidden %s); findings=%v reason=%q",
						verdict.Severity, c.ForbiddenSeverityAtLeast, verdict.Findings, verdict.Reason)
					passed = false
				}
			}
			if c.ExpectedAction != "" {
				if verdict.Action != c.ExpectedAction {
					t.Errorf("action=%s, want %s", verdict.Action, c.ExpectedAction)
					passed = false
				}
			}
			if len(c.MustIncludeFindingsSub) > 0 {
				combined := strings.Join(verdict.Findings, ",")
				for _, sub := range c.MustIncludeFindingsSub {
					if !strings.Contains(combined, sub) {
						t.Errorf("findings missing substring %q; got %v", sub, verdict.Findings)
						passed = false
					}
				}
			}

			recordResult(tier, passed)
		})
	}

	// Log the per-tier summary so CI output has a calibration snapshot.
	for tier, s := range stats {
		t.Logf("benchmark tier=%s pass=%d fail=%d", tier, s.pass, s.fail)
	}
}
