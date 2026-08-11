// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

func TestLogScanRedactsCredentialEvidenceBeforeForensicPersistence(t *testing.T) {
	logger := newTestLogger(t)
	runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(runtime)

	credential := "Authorization: Bearer " + strings.Repeat("private-token-", 4)
	source := scanner.InspectFindingSource{
		Scanner: "hook-rules", Target: "codex:PostToolUse", TargetType: "tool_response",
		Verdict: "alert", EvaluationID: "credential-redaction-evaluation",
		Findings: []scanner.InspectFinding{{
			RuleID: "SEC-BEARER", Title: "Bearer token in header",
			Severity: scanner.SeverityHigh, Confidence: 0.8,
			Evidence: credential, Tags: []string{"credential"},
		}},
	}

	_, scanID, err := logger.LogInspectFindingsWithCorrelation(t.Context(), source, ScanCorrelation{Connector: "codex"})
	if err != nil {
		t.Fatalf("log credential finding: %v", err)
	}
	rows, err := logger.store.ListScanFindings(scanID)
	if err != nil || len(rows) != 1 {
		t.Fatalf("persisted credential findings=%#v err=%v", rows, err)
	}
	row := rows[0]
	if !row.EvidenceSummary.Valid || !strings.HasPrefix(row.EvidenceSummary.String, "<redacted-sensitive ") {
		t.Fatalf("persisted evidence summary = %#v, want redaction placeholder", row.EvidenceSummary)
	}
	if strings.Contains(row.EvidenceSummary.String, credential) || strings.Contains(row.Target, credential) {
		t.Fatalf("persisted finding exposed raw credential: target=%q evidence=%q", row.Target, row.EvidenceSummary.String)
	}
	if row.RuleID.String != "SEC-BEARER" || row.Target != "codex:PostToolUse" {
		t.Fatalf("redaction discarded useful finding identity: %#v", row)
	}

	var fingerprint string
	if err := logger.store.db.QueryRow(
		`SELECT content_fingerprint FROM scan_findings WHERE scan_id = ?`, scanID,
	).Scan(&fingerprint); err != nil {
		t.Fatalf("load persisted content fingerprint: %v", err)
	}
	wantFingerprint := testFindingContentFingerprint(t, runtime, credential)
	if fingerprint != wantFingerprint {
		t.Fatalf("content fingerprint = %q, want keyed fingerprint %q", fingerprint, wantFingerprint)
	}
	rawSum := sha256.Sum256([]byte(credential))
	if unkeyed := hex.EncodeToString(rawSum[:])[:8]; fingerprint == unkeyed {
		t.Fatalf("content fingerprint retained unkeyed SHA prefix %q", unkeyed)
	}

	_, records := runtime.snapshot()
	if len(records) != 2 {
		t.Fatalf("generated records=%d, want finding plus scan summary", len(records))
	}
	body := securityActionBody(t, records[0])
	for field, value := range body {
		if strings.Contains(valueAsText(value), credential) {
			t.Fatalf("canonical finding field %q exposed raw credential: %#v", field, value)
		}
	}
}

func TestLogScanRedactsAllSecretValueFieldsAndClassifiers(t *testing.T) {
	logger := newTestLogger(t)
	runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(runtime)

	type secretCase struct {
		ruleID   string
		sourceID string
		category string
		tags     []string
		secret   string
		describe bool
	}
	cases := []secretCase{
		{ruleID: "SEC-X-DESCRIPTION", secret: "sec-description-" + strings.Repeat("a", 32), describe: true},
		{ruleID: "CS-SEC-CUSTOM", secret: "cs-secret-" + strings.Repeat("b", 32)},
		{ruleID: "SECRET-CUSTOM", secret: "secret-prefix-" + strings.Repeat("c", 32)},
		{ruleID: "JSON-SEC-CUSTOM", secret: "json-secret-" + strings.Repeat("g", 32)},
		{ruleID: "CRED-CUSTOM", secret: "cred-prefix-" + strings.Repeat("j", 32)},
		{ruleID: "CUSTOM-SECRET-SOURCE-ID", sourceID: "CS-SEC-ID-ONLY", secret: "id-secret-" + strings.Repeat("f", 32)},
		{ruleID: "CUSTOM-SECRET-TAG", tags: []string{"secret"}, secret: "tag-secret-" + strings.Repeat("d", 32)},
		{ruleID: "CUSTOM-SECRET-CATEGORY", category: "secret", secret: "category-secret-" + strings.Repeat("e", 32)},
		{ruleID: "CUSTOM-CREDENTIAL-TAG", tags: []string{"credential"}, secret: "credential-tag-" + strings.Repeat("h", 32)},
		{ruleID: "CUSTOM-CREDENTIAL-CATEGORY", category: "credential", secret: "credential-category-" + strings.Repeat("i", 32)},
	}

	findings := make([]scanner.Finding, 0, len(cases))
	wantFingerprint := make(map[string]string, len(cases))
	unkeyedFingerprint := make(map[string]string, len(cases))
	for _, tc := range cases {
		sourceID := tc.sourceID
		if sourceID == "" {
			sourceID = tc.ruleID + "-source"
		}
		finding := scanner.Finding{
			// ID is producer-controlled compatibility data and may itself carry
			// the matched value. The persistence boundary must clear it while
			// preserving the separately minted occurrence ID.
			ID: sourceID + ":" + tc.secret, RuleID: tc.ruleID, Category: tc.category,
			Title: "Source title containing " + tc.secret, Severity: scanner.SeverityHigh,
			Tags: append(append([]string(nil), tc.tags...), tc.secret), Scanner: "hook-rules",
			ContentFingerprint: tc.secret,
		}
		fingerprintSource := tc.secret
		if tc.describe {
			finding.Description = tc.secret
			finding.Location = tc.secret + "-location"
			finding.Remediation = tc.secret + "-remediation"
			finding.ExternalEndpoint = tc.secret + ".invalid"
			decision, err := json.Marshal(map[string]string{"matched": tc.secret})
			if err != nil {
				t.Fatal(err)
			}
			finding.DecisionPath = decision
		} else {
			finding.EvidenceSummary = tc.secret
		}
		wantFingerprint[tc.ruleID] = testFindingContentFingerprint(t, runtime, fingerprintSource)
		rawSum := sha256.Sum256([]byte(fingerprintSource))
		unkeyedFingerprint[tc.ruleID] = hex.EncodeToString(rawSum[:])[:8]
		findings = append(findings, finding)
	}

	result := &scanner.ScanResult{
		Scanner: "hook-rules", Target: "codex:PostToolUse", TargetType: "tool_response",
		Timestamp: time.Now().UTC(), Findings: findings,
	}
	corr := ScanCorrelation{
		Connector: "codex", EvaluationID: "secret-boundary-evaluation",
		RequestID: "secret-boundary-request", SessionID: "secret-boundary-session",
	}
	if err := logger.LogScanWithCorrelation(t.Context(), result, "alert", corr); err != nil {
		t.Fatalf("log classified secret findings: %v", err)
	}
	for index := range result.Findings {
		if result.Findings[index].ID != "" {
			t.Fatalf("secret finding %d retained producer ID %q", index, result.Findings[index].ID)
		}
		if result.Findings[index].FindingOccurrenceID == "" {
			t.Fatalf("secret finding %d lost canonical occurrence ID", index)
		}
	}

	rows, err := logger.store.db.Query(`
SELECT rule_id, title, severity, description, evidence_summary, location,
       remediation, tags, content_fingerprint, external_endpoint, decision_path,
       evaluation_id
FROM scan_findings WHERE scan_id = ?`, result.ScanID)
	if err != nil {
		t.Fatalf("query persisted secret findings: %v", err)
	}
	defer rows.Close()
	seen := make(map[string]bool, len(cases))
	for rows.Next() {
		var (
			ruleID, severity, fingerprint, evaluationID string
			title, description, evidence, location      sql.NullString
			remediation, tags, endpoint, decision       sql.NullString
		)
		if err := rows.Scan(
			&ruleID, &title, &severity, &description, &evidence, &location,
			&remediation, &tags, &fingerprint, &endpoint, &decision, &evaluationID,
		); err != nil {
			t.Fatalf("scan persisted secret finding: %v", err)
		}
		var tc *secretCase
		for index := range cases {
			if cases[index].ruleID == ruleID {
				tc = &cases[index]
				break
			}
		}
		if tc == nil {
			t.Fatalf("unexpected persisted rule %q", ruleID)
		}
		seen[ruleID] = true
		if title.String != redactedSecretFindingTitle || tags.String != `["secret","redacted"]` ||
			severity != string(scanner.SeverityHigh) ||
			evaluationID != corr.EvaluationID || fingerprint != wantFingerprint[ruleID] {
			t.Fatalf("secret identity/correlation changed for %s: title=%q tags=%q severity=%q evaluation=%q fingerprint=%q",
				ruleID, title.String, tags.String, severity, evaluationID, fingerprint)
		}
		for field, value := range map[string]string{
			"description": description.String, "evidence": evidence.String,
			"location": location.String, "remediation": remediation.String,
			"external_endpoint": endpoint.String, "decision_path": decision.String,
		} {
			if strings.Contains(value, tc.secret) {
				t.Fatalf("%s %s persisted raw credential %q", ruleID, field, value)
			}
			if strings.Contains(value, unkeyedFingerprint[ruleID]) || strings.Contains(value, "sha=") {
				t.Fatalf("%s %s persisted enumerable credential digest", ruleID, field)
			}
		}
		if tc.describe && (!strings.HasPrefix(description.String, "<redacted-sensitive ") ||
			!strings.HasPrefix(location.String, "<redacted-sensitive ") ||
			!strings.HasPrefix(remediation.String, "<redacted-sensitive ") ||
			!strings.HasPrefix(endpoint.String, "<redacted-sensitive ") ||
			!json.Valid([]byte(decision.String))) {
			t.Fatalf("SEC-X value fields were not safely projected: description=%q location=%q remediation=%q endpoint=%q decision=%q",
				description.String, location.String, remediation.String, endpoint.String, decision.String)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(seen) != len(cases) {
		t.Fatalf("persisted classified secrets=%v, want all %d cases", seen, len(cases))
	}

	var rawJSON string
	if err := logger.store.db.QueryRow(`SELECT raw_json FROM scan_results WHERE id = ?`, result.ScanID).Scan(&rawJSON); err != nil {
		t.Fatalf("load persisted scan JSON: %v", err)
	}
	_, records := runtime.snapshot()
	for _, tc := range cases {
		if strings.Contains(rawJSON, tc.secret) {
			t.Fatalf("scan_results.raw_json exposed %s credential", tc.ruleID)
		}
		if strings.Contains(rawJSON, unkeyedFingerprint[tc.ruleID]) || strings.Contains(rawJSON, "sha=") {
			t.Fatalf("scan_results.raw_json exposed %s unkeyed credential digest", tc.ruleID)
		}
		for _, record := range records {
			for field, value := range securityActionBody(t, record) {
				if strings.Contains(valueAsText(value), tc.secret) {
					t.Fatalf("canonical record field %q exposed %s credential", field, tc.ruleID)
				}
				if strings.Contains(valueAsText(value), unkeyedFingerprint[tc.ruleID]) ||
					strings.Contains(valueAsText(value), "sha=") {
					t.Fatalf("canonical record field %q exposed %s unkeyed credential digest", field, tc.ruleID)
				}
			}
		}
	}
}

func TestLogScanRedactsBuiltInCodeGuardCredentialFinding(t *testing.T) {
	logger := newTestLogger(t)
	runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(runtime)

	credential := "codeguard-private-value-" + strings.Repeat("q", 24)
	line := `api_key = "` + credential + `"`
	findings := scanner.NewCodeGuardScanner("").ScanContent("app.py", line)
	if len(findings) != 1 || findings[0].RuleID != "CG-CRED-001" ||
		findings[0].Category != "cred" || !strings.Contains(findings[0].Description, credential) {
		t.Fatalf("unexpected CodeGuard credential fixture: %#v", findings)
	}
	result := &scanner.ScanResult{
		Scanner: "codeguard", Target: "app.py", TargetType: "code",
		Timestamp: time.Now().UTC(), Findings: findings,
	}
	if err := logger.LogScanWithCorrelation(
		t.Context(),
		result,
		"alert",
		ScanCorrelation{Connector: "codex", EvaluationID: "codeguard-secret-boundary"},
	); err != nil {
		t.Fatalf("log CodeGuard credential finding: %v", err)
	}

	var title, description, tags, fingerprint string
	if err := logger.store.db.QueryRow(`
SELECT title, description, tags, content_fingerprint
FROM scan_findings WHERE scan_id = ?`, result.ScanID).Scan(
		&title, &description, &tags, &fingerprint,
	); err != nil {
		t.Fatalf("load persisted CodeGuard finding: %v", err)
	}
	if title != redactedSecretFindingTitle || tags != `["secret","redacted"]` ||
		strings.Contains(description, credential) ||
		!strings.HasPrefix(description, "<redacted-sensitive ") {
		t.Fatalf("CodeGuard credential was not redacted: title=%q description=%q tags=%q", title, description, tags)
	}
	if len(fingerprint) != 8 {
		t.Fatalf("CodeGuard fingerprint length=%d, want 8", len(fingerprint))
	}
	if _, err := hex.DecodeString(fingerprint); err != nil {
		t.Fatalf("CodeGuard fingerprint is not canonical hex: %q", fingerprint)
	}

	var rawJSON string
	if err := logger.store.db.QueryRow(
		`SELECT raw_json FROM scan_results WHERE id = ?`, result.ScanID,
	).Scan(&rawJSON); err != nil {
		t.Fatalf("load persisted CodeGuard scan JSON: %v", err)
	}
	if strings.Contains(rawJSON, credential) {
		t.Fatal("CodeGuard credential survived in scan_results.raw_json")
	}
	_, records := runtime.snapshot()
	for _, record := range records {
		for field, value := range securityActionBody(t, record) {
			if strings.Contains(valueAsText(value), credential) {
				t.Fatalf("canonical CodeGuard record field %q exposed credential", field)
			}
		}
	}
}

func testFindingContentFingerprint(
	t *testing.T,
	fingerprinter RuntimeV8FindingContentFingerprinter,
	evidence string,
) string {
	t.Helper()
	fingerprint, err := fingerprinter.FingerprintRuntimeV8FindingContent(evidence)
	if err != nil {
		t.Fatalf("fingerprint finding evidence: %v", err)
	}
	if !isCanonicalContentFingerprint(fingerprint) {
		t.Fatalf("finding fingerprint is not canonical: %q", fingerprint)
	}
	return fingerprint
}

func valueAsText(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []string:
		return strings.Join(typed, " ")
	case []any:
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			parts = append(parts, valueAsText(item))
		}
		return strings.Join(parts, " ")
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys)*2)
		for _, key := range keys {
			parts = append(parts, key, valueAsText(typed[key]))
		}
		return strings.Join(parts, " ")
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", typed)
	}
}

func TestValueAsTextRecursesIntoNestedCanonicalValues(t *testing.T) {
	raw := map[string]any{
		"outer": map[string]any{
			"nested": []any{"sensitive-marker", 42, true},
		},
	}
	got := valueAsText(raw)
	for _, want := range []string{"outer", "nested", "sensitive-marker", "42", "true"} {
		if !strings.Contains(got, want) {
			t.Fatalf("valueAsText(%#v) = %q, missing %q", raw, got, want)
		}
	}
}
