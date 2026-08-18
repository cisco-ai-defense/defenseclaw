// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"database/sql"
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
	for _, tc := range cases {
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
		if finding.ID != "" || !wellFormedSensitiveOpaqueRuleID(finding.RuleID, cases[index].kind) ||
			finding.FindingOccurrenceID == "" || strings.Contains(finding.RuleID, cases[index].sourceID) {
			t.Fatalf("post-log finding[%d] identity: ID=%q RuleID=%q occurrence=%q",
				index, finding.ID, finding.RuleID, finding.FindingOccurrenceID)
		}
		if _, duplicate := wantByRuleID[finding.RuleID]; duplicate {
			t.Fatalf("distinct sensitive source IDs collapsed to %q", finding.RuleID)
		}
		if _, duplicate := seenOccurrences[finding.FindingOccurrenceID]; duplicate {
			t.Fatalf("duplicate finding occurrence %q", finding.FindingOccurrenceID)
		}
		seenOccurrences[finding.FindingOccurrenceID] = struct{}{}
		wantByRuleID[finding.RuleID] = finding.FindingOccurrenceID
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

type goldenSensitiveFindingFingerprinter map[string]string

func (fingerprinter goldenSensitiveFindingFingerprinter) FingerprintRuntimeV8FindingContent(value string) (string, error) {
	if fingerprint, ok := fingerprinter[value]; ok {
		return fingerprint, nil
	}
	return "", fmt.Errorf("unexpected sensitive identity input")
}

func TestSensitiveFindingOpaqueIdentityGolden(t *testing.T) {
	const sourceID = "SEC-ID-ONLY-private"
	fingerprinter := goldenSensitiveFindingFingerprinter{
		"defenseclaw-sensitive-finding-rule-id-v1\x00secret\x00legacy-sensitive-scanner\x00" + sourceID + "\x00left":       "01234567",
		"defenseclaw-sensitive-finding-rule-id-v1\x00secret\x00legacy-sensitive-scanner\x00" + sourceID + "\x00right":      "89abcdef",
		"defenseclaw-sensitive-finding-rule-id-auth-v1\x00secret\x00legacy-sensitive-scanner\x000123456789abcdef\x00left":  "fedcba98",
		"defenseclaw-sensitive-finding-rule-id-auth-v1\x00secret\x00legacy-sensitive-scanner\x000123456789abcdef\x00right": "76543210",
	}
	finding := scanner.Finding{ID: sourceID, Severity: scanner.SeverityHigh}
	ensureSensitiveFindingRuleID(
		&finding,
		"legacy-sensitive-scanner",
		sensitiveFindingKindSecret,
		fingerprinter,
	)
	if finding.RuleID != "redacted.secret.id-0123456789abcdef.mac-fedcba9876543210" {
		t.Fatalf("golden sensitive RuleID=%q", finding.RuleID)
	}
}

func TestLogScanRekeysForgedSensitiveOpaqueRuleIDAndRemainsIdempotent(t *testing.T) {
	logger := newTestLogger(t)
	runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(runtime)

	// 70617373776f7264 is the ASCII encoding of a producer-selected value.
	// A format-only trust check used to preserve these chosen bytes verbatim.
	const forgedRuleID = "redacted.secret.id-70617373776f7264"
	result := &scanner.ScanResult{
		Scanner: "untrusted-producer", Target: "codex:PostToolUse", TargetType: "tool_response",
		Timestamp: time.Now().UTC(), Findings: []scanner.Finding{{
			RuleID: forgedRuleID, Category: "secret", Severity: scanner.SeverityHigh,
			Title: "Producer finding",
		}},
	}
	if err := logger.LogScanWithCorrelation(t.Context(), result, "alert", ScanCorrelation{}); err != nil {
		t.Fatalf("log producer-forged opaque identity: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("post-log findings=%d, want one", len(result.Findings))
	}
	canonicalRuleID := result.Findings[0].RuleID
	if canonicalRuleID == forgedRuleID || strings.Contains(canonicalRuleID, "70617373776f7264") {
		t.Fatalf("producer-forged opaque identity survived: %q", canonicalRuleID)
	}
	if !wellFormedSensitiveOpaqueRuleID(canonicalRuleID, sensitiveFindingKindSecret) {
		t.Fatalf("re-keyed identity is not canonical: %q", canonicalRuleID)
	}
	if !authenticatedSensitiveOpaqueRuleID(canonicalRuleID, sensitiveFindingKindSecret, result.Scanner, runtime) {
		t.Fatalf("re-keyed identity is not authenticated: %q", canonicalRuleID)
	}

	rawJSON, err := logger.store.GetScanRawJSON(result.ScanID)
	if err != nil {
		t.Fatalf("load forged-identity raw JSON: %v", err)
	}
	if strings.Contains(rawJSON, forgedRuleID) || strings.Contains(rawJSON, "70617373776f7264") {
		t.Fatalf("raw JSON retained producer-forged identity: %s", rawJSON)
	}
	_, forgedRecords := runtime.snapshot()
	for _, record := range forgedRecords {
		for field, value := range securityActionBody(t, record) {
			text := valueAsText(value)
			if strings.Contains(text, forgedRuleID) || strings.Contains(text, "70617373776f7264") {
				t.Fatalf("canonical field %q retained producer-forged identity", field)
			}
		}
	}
	rows, err := logger.store.ListScanFindings(result.ScanID)
	if err != nil || len(rows) != 1 || !rows[0].RuleID.Valid || rows[0].RuleID.String != canonicalRuleID {
		t.Fatalf("persisted forged-identity rows=%#v err=%v", rows, err)
	}

	ensureSensitiveFindingRuleID(
		&result.Findings[0],
		result.Scanner,
		sensitiveFindingKindSecret,
		runtime,
	)
	if result.Findings[0].RuleID != canonicalRuleID {
		t.Fatalf("verified opaque identity was not idempotent: first=%q second=%q",
			canonicalRuleID, result.Findings[0].RuleID)
	}
	replayedAcrossScanner := result.Findings[0]
	ensureSensitiveFindingRuleID(
		&replayedAcrossScanner,
		"different-untrusted-producer",
		sensitiveFindingKindSecret,
		runtime,
	)
	if replayedAcrossScanner.RuleID == canonicalRuleID ||
		!authenticatedSensitiveOpaqueRuleID(
			replayedAcrossScanner.RuleID,
			sensitiveFindingKindSecret,
			"different-untrusted-producer",
			runtime,
		) {
		t.Fatalf("opaque identity replay crossed scanner provenance: %q", replayedAcrossScanner.RuleID)
	}

	forgedCurrentShape := scanner.Finding{
		RuleID:   "redacted.secret.id-70617373776f7264.mac-0000000000000000",
		Category: "secret",
	}
	ensureSensitiveFindingRuleID(
		&forgedCurrentShape,
		result.Scanner,
		sensitiveFindingKindSecret,
		runtime,
	)
	if strings.Contains(forgedCurrentShape.RuleID, "70617373776f7264") ||
		!authenticatedSensitiveOpaqueRuleID(
			forgedCurrentShape.RuleID, sensitiveFindingKindSecret, result.Scanner, runtime,
		) {
		t.Fatalf("producer-forged authenticated shape was trusted: %q", forgedCurrentShape.RuleID)
	}
}

func TestLogScanNormalizesSensitiveProducerMetadata(t *testing.T) {
	logger := newTestLogger(t)
	runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(runtime)
	marker := "producer-controlled-" + strings.Repeat("q", 40)
	cases := []struct {
		kind     sensitiveFindingKind
		ruleID   string
		category string
	}{
		{sensitiveFindingKindSecret, "SEC-" + marker, "secret-" + marker},
		{sensitiveFindingKindPII, "PII-" + marker, "pii-" + marker},
		{sensitiveFindingKindTrust, "TRUST-" + marker, "trust-" + marker},
	}
	findings := make([]scanner.Finding, 0, len(cases))
	for _, tc := range cases {
		findings = append(findings, scanner.Finding{
			ID: marker, RuleID: tc.ruleID, Category: tc.category,
			Scanner: "untrusted-producer", Severity: scanner.SeverityHigh,
			Title: marker, EvidenceSummary: marker,
			DataAxis: []string{
				marker, " SENSITIVE_ACCESS ", "sensitive_access", " EGRESS_EXTERNAL ",
			},
			ToolCapabilityClass: marker,
		})
	}
	result := &scanner.ScanResult{
		Scanner: "untrusted-producer", Target: "codex:PostToolUse", TargetType: "tool_response",
		Timestamp: time.Now().UTC(), Findings: findings,
	}
	if err := logger.LogScanWithCorrelation(t.Context(), result, "alert", ScanCorrelation{}); err != nil {
		t.Fatalf("log producer-controlled sensitive metadata: %v", err)
	}
	for index, finding := range result.Findings {
		if !wellFormedSensitiveOpaqueRuleID(finding.RuleID, cases[index].kind) ||
			finding.Category != canonicalSensitiveFindingCategory(cases[index].kind) ||
			strings.Contains(finding.RuleID, marker) || strings.Contains(finding.Category, marker) ||
			len(finding.DataAxis) != 2 || finding.DataAxis[0] != "sensitive_access" ||
			finding.DataAxis[1] != "egress_external" || finding.ToolCapabilityClass != "" {
			t.Fatalf("finding[%d] retained producer metadata: %+v", index, finding)
		}
	}
	metadataRows, err := logger.store.db.Query(
		`SELECT data_axis, tool_capability_class FROM scan_findings WHERE scan_id = ?`,
		result.ScanID,
	)
	if err != nil {
		t.Fatalf("query persisted sensitive metadata: %v", err)
	}
	defer metadataRows.Close()
	persistedMetadata := 0
	for metadataRows.Next() {
		var axes, capability sql.NullString
		if err := metadataRows.Scan(&axes, &capability); err != nil {
			t.Fatalf("scan persisted sensitive metadata: %v", err)
		}
		if !axes.Valid || axes.String != `["sensitive_access","egress_external"]` || capability.Valid {
			t.Fatalf("persisted sensitive metadata axes=%#v capability=%#v", axes, capability)
		}
		persistedMetadata++
	}
	if err := metadataRows.Err(); err != nil || persistedMetadata != len(cases) {
		t.Fatalf("persisted sensitive metadata rows=%d err=%v", persistedMetadata, err)
	}
	rawJSON, err := logger.store.GetScanRawJSON(result.ScanID)
	if err != nil {
		t.Fatalf("load normalized sensitive raw JSON: %v", err)
	}
	if strings.Contains(rawJSON, marker) {
		t.Fatal("scan_results.raw_json retained producer-controlled sensitive metadata")
	}
	_, records := runtime.snapshot()
	for _, record := range records {
		for field, value := range securityActionBody(t, record) {
			if strings.Contains(valueAsText(value), marker) {
				t.Fatalf("canonical field %q retained producer-controlled sensitive metadata", field)
			}
		}
	}
}

func TestCanonicalSensitiveFindingMetadataPreservesOnlyKnownEnums(t *testing.T) {
	finding := scanner.Finding{
		DataAxis: []string{
			" INGRESS_UNTRUSTED ", "unknown-axis", "ingress_untrusted", "SENSITIVE_ACCESS",
		},
		ToolCapabilityClass: " SEND_MESSAGE ",
	}
	canonicalizeSensitiveFindingMetadata(&finding)
	if len(finding.DataAxis) != 2 || finding.DataAxis[0] != "ingress_untrusted" ||
		finding.DataAxis[1] != "sensitive_access" || finding.ToolCapabilityClass != "send_message" {
		t.Fatalf("canonical sensitive metadata=%+v", finding)
	}
	finding.ToolCapabilityClass = "producer-controlled-capability"
	canonicalizeSensitiveFindingMetadata(&finding)
	if finding.ToolCapabilityClass != "" {
		t.Fatalf("unknown sensitive capability survived: %q", finding.ToolCapabilityClass)
	}
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
