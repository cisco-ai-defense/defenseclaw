// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

func TestLogScanPreservesOpaqueIdentityForSensitiveIDOnlyFindings(t *testing.T) {
	logger := newTestLogger(t)
	runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(runtime)

	piiMarker := strings.Join([]string{"731", "42", "9816"}, "-")
	trustMarker := strings.Join([]string{"replace", "the", "earlier", "instructions"}, " ")
	secretMarker := "private-detector-value-" + strings.Repeat("z", 32)
	type identityCase struct {
		kind     sensitiveFindingKind
		sourceID string
		tags     []string
	}
	cases := []identityCase{
		{kind: sensitiveFindingKindSecret, sourceID: "SEC-ID-ONLY-" + secretMarker},
		{kind: sensitiveFindingKindPII, sourceID: "PII-ID-ONLY-" + piiMarker},
		{kind: sensitiveFindingKindTrust, sourceID: "TRUST-ID-ONLY-" + trustMarker},
	}

	findings := make([]scanner.Finding, 0, len(cases))
	wantRuleIDs := make(map[string]string, len(cases))
	for _, tc := range cases {
		wantRuleIDs[tc.sourceID] = expectedSensitiveFindingRuleID(
			t,
			runtime,
			"legacy-sensitive-scanner",
			tc.kind,
			tc.sourceID,
		)
		findings = append(findings, scanner.Finding{
			ID: tc.sourceID, Severity: scanner.SeverityHigh,
			Title: tc.sourceID, Description: tc.sourceID,
			Scanner: "legacy-sensitive-scanner", Tags: tc.tags,
		})
	}
	result := &scanner.ScanResult{
		Scanner: "legacy-sensitive-scanner", Target: "codex:PostToolUse",
		TargetType: "tool_response", Timestamp: time.Now().UTC(), Findings: findings,
	}
	if err := logger.LogScanWithCorrelation(t.Context(), result, "alert", ScanCorrelation{
		Connector: "codex", EvaluationID: "id-only-sensitive-evaluation",
	}); err != nil {
		t.Fatalf("log ID-only sensitive findings: %v", err)
	}
	if result.ScanID == "" || result.Verdict != "alert" {
		t.Fatalf("post-log scan identity/verdict=%q/%q", result.ScanID, result.Verdict)
	}

	wantByRuleID := make(map[string]string, len(cases))
	seenOccurrences := make(map[string]struct{}, len(cases))
	for index, finding := range result.Findings {
		wantRuleID := wantRuleIDs[cases[index].sourceID]
		if finding.ID != "" || finding.RuleID != wantRuleID || finding.FindingOccurrenceID == "" {
			t.Fatalf("post-log finding[%d] identity: ID=%q RuleID=%q occurrence=%q, want RuleID=%q",
				index, finding.ID, finding.RuleID, finding.FindingOccurrenceID, wantRuleID)
		}
		if _, duplicate := seenOccurrences[finding.FindingOccurrenceID]; duplicate {
			t.Fatalf("duplicate finding occurrence %q", finding.FindingOccurrenceID)
		}
		seenOccurrences[finding.FindingOccurrenceID] = struct{}{}
		wantByRuleID[wantRuleID] = finding.FindingOccurrenceID
	}

	rows, err := logger.store.ListScanFindings(result.ScanID)
	if err != nil || len(rows) != len(cases) {
		t.Fatalf("persisted ID-only findings=%#v err=%v", rows, err)
	}
	for _, row := range rows {
		if !row.RuleID.Valid || wantByRuleID[row.RuleID.String] != row.ID {
			t.Fatalf("persisted canonical identity=%#v want=%v", row, wantByRuleID)
		}
	}

	rawJSON, err := logger.store.GetScanRawJSON(result.ScanID)
	if err != nil {
		t.Fatalf("load ID-only raw_json: %v", err)
	}
	_, records := runtime.snapshot()
	if len(records) != len(cases)+1 {
		t.Fatalf("generated records=%d, want %d findings plus summary", len(records), len(cases))
	}
	for index := range cases {
		body := securityActionBody(t, records[index])
		if body["defenseclaw.finding.rule_id"] != result.Findings[index].RuleID ||
			body["defenseclaw.finding.id"] != result.Findings[index].FindingOccurrenceID {
			t.Fatalf("canonical finding[%d] identity=%#v", index, body)
		}
	}
	for _, tc := range cases {
		if strings.Contains(rawJSON, tc.sourceID) {
			t.Fatalf("scan_results.raw_json retained producer ID %q", tc.sourceID)
		}
		for _, record := range records {
			for field, value := range securityActionBody(t, record) {
				if strings.Contains(valueAsText(value), tc.sourceID) {
					t.Fatalf("canonical field %q retained producer ID %q", field, tc.sourceID)
				}
			}
		}
	}
}

func expectedSensitiveFindingRuleID(
	t *testing.T,
	fingerprinter RuntimeV8FindingContentFingerprinter,
	scannerName string,
	kind sensitiveFindingKind,
	sourceID string,
) string {
	t.Helper()
	identityInput := strings.Join([]string{
		"defenseclaw-sensitive-finding-rule-id-v1",
		string(kind),
		strings.TrimSpace(scannerName),
		strings.TrimSpace(sourceID),
	}, "\x00")
	left, err := fingerprinter.FingerprintRuntimeV8FindingContent(identityInput + "\x00left")
	if err != nil {
		t.Fatal(err)
	}
	right, err := fingerprinter.FingerprintRuntimeV8FindingContent(identityInput + "\x00right")
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("redacted.%s.id-%s%s", kind, left, right)
}

func TestSensitiveFindingIDFailsClosedWhenKeyedIdentityIsUnavailable(t *testing.T) {
	finding := scanner.Finding{ID: "SEC-ID-ONLY-private", Severity: scanner.SeverityHigh}
	ensureSensitiveFindingRuleID(
		&finding,
		"legacy-sensitive-scanner",
		sensitiveFindingKindSecret,
		&failingFindingFingerprinterRuntime{},
	)
	if finding.RuleID != "redacted.secret.unknown" {
		t.Fatalf("failed keyed identity RuleID=%q", finding.RuleID)
	}
}
