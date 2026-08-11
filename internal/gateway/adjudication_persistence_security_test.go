// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

func TestAdjudicationModelTextNeverBecomesFindingIdentityOrPersistedEvidence(t *testing.T) {
	directive := strings.Join([]string{"override", "all", "earlier", "instructions"}, " ")
	personalValue := strings.Join([]string{"742", "31", "9056"}, "-")
	tests := []struct {
		name       string
		category   string
		pattern    string
		findingID  string
		findingCat string
	}{
		{name: "injection", category: "injection", pattern: directive, findingID: "JUDGE-ADJ-INJECTION", findingCat: CatPromptInjection},
		{name: "PII", category: "pii", pattern: personalValue, findingID: "JUDGE-ADJ-PII", findingCat: CatPIIExposure},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reasoning := tc.pattern + " model explanation"
			response, err := json.Marshal(map[string]any{
				"findings": []map[string]string{
					{"pattern": tc.pattern, "verdict": "true_positive", "reasoning": reasoning},
					{"pattern": tc.pattern + " duplicate", "verdict": "true_positive", "reasoning": reasoning},
				},
				"overall_threat": true,
				"severity":       "HIGH",
			})
			if err != nil {
				t.Fatal(err)
			}
			verdict := parseAdjudicationResponse(string(response), tc.category)
			if verdict == nil || len(verdict.Findings) != 1 || verdict.Findings[0] != tc.findingID {
				t.Fatalf("adjudication identity=%#v, want one stable %s finding", verdict, tc.findingID)
			}
			for _, sourceText := range []string{tc.pattern, reasoning} {
				if strings.Contains(verdict.Reason, sourceText) || strings.Contains(strings.Join(verdict.Findings, " "), sourceText) {
					t.Fatal("model-supplied adjudication text reached the live verdict")
				}
			}

			normalized := NormalizeScanVerdict(verdict)
			if len(normalized) != 1 || normalized[0].CanonicalID != tc.findingID ||
				normalized[0].OriginalID != tc.findingID || normalized[0].Category != tc.findingCat {
				t.Fatalf("normalized adjudication=%#v", normalized)
			}
			for _, sourceText := range []string{tc.pattern, reasoning} {
				identity, err := json.Marshal(normalized)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(identity), sourceText) {
					t.Fatal("model-supplied adjudication text reached normalized identity")
				}
			}

			store, logger := testStoreAndLogger(t)
			_, scanID, err := logger.LogInspectFindingsWithCorrelation(t.Context(), scanner.InspectFindingSource{
				Scanner: "hook-rules", Target: "codex:PostToolUse", TargetType: "tool_response",
				Verdict: verdict.Action, Findings: normalizedFindingsToInspect(normalized, verdict.Severity),
			}, audit.ScanCorrelation{Connector: "codex"})
			if err != nil {
				t.Fatalf("persist adjudication finding: %v", err)
			}
			rows, err := store.ListScanFindings(scanID)
			if err != nil || len(rows) != 1 {
				t.Fatalf("persisted adjudication rows=%#v err=%v", rows, err)
			}
			rawJSON, err := store.GetScanRawJSON(scanID)
			if err != nil {
				t.Fatalf("GetScanRawJSON: %v", err)
			}
			events, err := store.ListEvents(100)
			if err != nil {
				t.Fatalf("ListEvents: %v", err)
			}
			eventJSON, err := json.Marshal(events)
			if err != nil {
				t.Fatal(err)
			}
			rowJSON, err := json.Marshal(rows)
			if err != nil {
				t.Fatal(err)
			}
			for _, sourceText := range []string{tc.pattern, reasoning} {
				if strings.Contains(rawJSON, sourceText) || strings.Contains(string(eventJSON), sourceText) ||
					strings.Contains(string(rowJSON), sourceText) {
					t.Fatal("model-supplied adjudication text crossed the persistence boundary")
				}
			}
		})
	}
}
