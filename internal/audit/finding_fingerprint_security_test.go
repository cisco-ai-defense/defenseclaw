// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

func TestLogScanKeysAllEvidenceFingerprintsAndDeduplicatesRepeats(t *testing.T) {
	logger := newTestLogger(t)
	runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(runtime)

	sharedEvidence := strings.Join([]string{"shared", "correlation", strings.Repeat("v", 24)}, "-")
	differentEvidence := sharedEvidence + "-different"
	wantShared := testFindingContentFingerprint(t, runtime, sharedEvidence)
	wantDifferent := testFindingContentFingerprint(t, runtime, differentEvidence)
	rawSum := sha256.Sum256([]byte(sharedEvidence))
	unkeyedShared := hex.EncodeToString(rawSum[:])[:8]
	if wantShared == wantDifferent || wantShared == unkeyedShared {
		t.Fatalf("test keyed fingerprints are not separated: shared=%q different=%q unkeyed=%q",
			wantShared, wantDifferent, unkeyedShared)
	}

	result := &scanner.ScanResult{
		Scanner: "hook-rules", Target: "codex:PostToolUse", TargetType: "tool_response",
		Timestamp: time.Now().UTC(),
		Findings: []scanner.Finding{
			{RuleID: "SEC-SHARED", Category: "credential-leak", Severity: scanner.SeverityHigh,
				Title: "secret", EvidenceSummary: sharedEvidence, DataAxis: []string{"sensitive_access"}},
			{RuleID: "LP-PII-DATA", Category: "pii-exposure", Severity: scanner.SeverityHigh,
				Title: "pii", EvidenceSummary: sharedEvidence, DataAxis: []string{"sensitive_access"}},
			{RuleID: "LP-PII-DATA", Category: "pii-exposure", Severity: scanner.SeverityHigh,
				Title: "pii repeat", EvidenceSummary: sharedEvidence, DataAxis: []string{"sensitive_access"}},
			{RuleID: "C2-SHARED-EGRESS", Category: "network", Severity: scanner.SeverityHigh,
				Title: "egress", EvidenceSummary: sharedEvidence, DataAxis: []string{"egress_external"}},
			{RuleID: "C2-DIFFERENT-EGRESS", Category: "network", Severity: scanner.SeverityHigh,
				Title: "different egress", EvidenceSummary: differentEvidence, DataAxis: []string{"egress_external"}},
		},
	}
	corr := ScanCorrelation{SessionID: "keyed-repeat-session", AgentInstanceID: "keyed-repeat-agent"}
	if err := logger.LogScanWithCorrelation(t.Context(), result, "alert", corr); err != nil {
		t.Fatalf("log keyed findings: %v", err)
	}

	rows, err := logger.store.db.Query(`
SELECT rule_id, content_fingerprint FROM scan_findings
WHERE scan_id = ? ORDER BY rowid`, result.ScanID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	counts := make(map[string]int)
	fingerprints := make(map[string]string)
	for rows.Next() {
		var ruleID string
		var fingerprint sql.NullString
		if err := rows.Scan(&ruleID, &fingerprint); err != nil {
			t.Fatal(err)
		}
		if !fingerprint.Valid || !isCanonicalContentFingerprint(fingerprint.String) {
			t.Fatalf("%s fingerprint=%#v, want keyed 8-hex", ruleID, fingerprint)
		}
		counts[ruleID]++
		fingerprints[ruleID] = fingerprint.String
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, ruleID := range []string{"SEC-SHARED", "LP-PII-DATA", "C2-SHARED-EGRESS"} {
		if fingerprints[ruleID] != wantShared {
			t.Fatalf("%s fingerprint=%q, want shared keyed token %q", ruleID, fingerprints[ruleID], wantShared)
		}
	}
	if counts["LP-PII-DATA"] != 2 || fingerprints["C2-DIFFERENT-EGRESS"] != wantDifferent {
		t.Fatalf("keyed persistence counts=%v fingerprints=%v", counts, fingerprints)
	}

	window, err := logger.store.ListRecentFindingsInSession(corr.SessionID, corr.AgentInstanceID, corr.AgentID, 10)
	if err != nil {
		t.Fatal(err)
	}
	piiCount := 0
	for _, row := range window {
		if row.RuleID.Valid && row.RuleID.String == "LP-PII-DATA" {
			piiCount++
		}
	}
	if len(window) != 4 || piiCount != 1 {
		t.Fatalf("keyed repeat was not deduplicated: rows=%#v", window)
	}

	rawJSON, err := logger.store.GetScanRawJSON(result.ScanID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rawJSON, unkeyedShared) || strings.Contains(rawJSON, `"content_fingerprint":"`+unkeyedShared+`"`) {
		t.Fatal("unkeyed SHA prefix crossed the scan persistence boundary")
	}
}

type failingFindingFingerprinterRuntime struct {
	*testRuntimeV8Emitter
}

func (*failingFindingFingerprinterRuntime) FingerprintRuntimeV8FindingContent(string) (string, error) {
	return "", fmt.Errorf("test keyed fingerprint unavailable")
}

func TestLogScanClearsProducerFingerprintWhenKeyedHasherFails(t *testing.T) {
	logger := newTestLogger(t)
	runtime := &failingFindingFingerprinterRuntime{
		testRuntimeV8Emitter: newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary),
	}
	logger.SetRuntimeV8Emitter(runtime)
	evidence := strings.Join([]string{"untrusted", "producer", "fingerprint"}, "-")
	sum := sha256.Sum256([]byte(evidence))
	unkeyed := hex.EncodeToString(sum[:])[:8]
	result := &scanner.ScanResult{
		Scanner: "hook-rules", Target: "codex:PostToolUse", Timestamp: time.Now().UTC(),
		Findings: []scanner.Finding{{
			RuleID: "C2-FAIL-CLOSED", Category: "network", Severity: scanner.SeverityHigh,
			Title: "egress", EvidenceSummary: evidence, ContentFingerprint: unkeyed,
		}},
	}
	if err := logger.LogScanWithCorrelation(t.Context(), result, "alert", ScanCorrelation{}); err != nil {
		t.Fatal(err)
	}
	var fingerprint sql.NullString
	if err := logger.store.db.QueryRow(
		`SELECT content_fingerprint FROM scan_findings WHERE scan_id = ?`, result.ScanID,
	).Scan(&fingerprint); err != nil {
		t.Fatal(err)
	}
	if fingerprint.Valid || result.Findings[0].ContentFingerprint != "" {
		t.Fatalf("key failure retained producer fingerprint: row=%#v source=%q", fingerprint, result.Findings[0].ContentFingerprint)
	}
}
