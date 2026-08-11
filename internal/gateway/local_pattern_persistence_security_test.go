// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

func TestLocalPatternSensitiveRawShapesNormalizeWithoutIdentityLeak(t *testing.T) {
	secretValue := "local-Q7m2V9x4K8p6R3t1W5y0N8c4"
	header := strings.Join([]string{"Author", "ization"}, "") + ": " +
		strings.Join([]string{"Bear", "er"}, "") + " " + secretValue
	assignment := strings.Join([]string{"api", "key"}, "_") + " = " + secretValue
	directive := strings.Join([]string{"developer", "mode", "enabled"}, " ")
	prefixDirective := "TRUST-CUSTOM:" + directive
	localPrefixDirective := "LP-INJ-CUSTOM:" + directive
	personalValue := strings.Join([]string{"4773", "9182", "6405", "7399"}, ".")
	personalRecord := "payment card: " + personalValue
	withLocalPatternsRestored(t)
	if err := ApplyLocalPatternsOverride(&guardrail.LocalPatterns{
		Version:        1,
		Injection:      []string{directive},
		PIIDataRegexes: []string{`\b4\d{3}(?:\.\d{4}){3}\b`},
	}); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		raw         string
		category    string
		idPrefix    string
		sensitive   string
		stableTitle string
	}{
		{name: "authorization header", raw: header, category: CatCredentialLeak, idPrefix: "LP-SECRET-", sensitive: secretValue, stableTitle: localCredentialFindingTitle},
		{name: "assignment", raw: assignment, category: CatCredentialLeak, idPrefix: "LP-SECRET-", sensitive: secretValue, stableTitle: localCredentialFindingTitle},
		{name: "injection phrase", raw: directive, category: CatPromptInjection, idPrefix: "LP-INJ-", sensitive: directive, stableTitle: localInjectionFindingTitle},
		{name: "canonical-prefix injection", raw: prefixDirective, category: CatPromptInjection, idPrefix: "LP-INJ-", sensitive: directive, stableTitle: localInjectionFindingTitle},
		{name: "local-prefix injection", raw: localPrefixDirective, category: CatPromptInjection, idPrefix: "LP-INJ-", sensitive: directive, stableTitle: localInjectionFindingTitle},
		{name: "PII value", raw: "pii-data:" + personalRecord, category: CatPIIExposure, idPrefix: "LP-PII-", sensitive: personalValue, stableTitle: localPIIFindingTitle},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			normalized := NormalizeScanVerdict(&ScanVerdict{
				Scanner: "local-pattern", Severity: "HIGH", Findings: []string{tc.raw},
			})
			if len(normalized) != 1 {
				t.Fatalf("normalized findings=%#v", normalized)
			}
			finding := normalized[0]
			if !strings.HasPrefix(finding.CanonicalID, tc.idPrefix) || finding.Category != tc.category ||
				finding.Title != tc.stableTitle || finding.OriginalID != finding.CanonicalID {
				t.Fatalf("unsafe normalized identity=%#v", finding)
			}
			for field, value := range map[string]string{
				"canonical_id": finding.CanonicalID, "original_id": finding.OriginalID, "title": finding.Title,
			} {
				if strings.Contains(value, tc.sensitive) {
					t.Fatalf("%s retained sensitive local match in %s", tc.name, field)
				}
			}
			if !strings.Contains(finding.Evidence, tc.sensitive) {
				t.Fatalf("%s evidence lost source value before persistence boundary: %#v", tc.name, finding)
			}
		})
	}
}

func TestLocalPatternSensitiveFindingsAreNeutralizedAcrossPersistence(t *testing.T) {
	secretValue := "persist-H8q1F4s7N2v5C9m3R6t0W8y4"
	header := strings.Join([]string{"Author", "ization"}, "") + ": " +
		strings.Join([]string{"Bear", "er"}, "") + " " + secretValue
	assignment := strings.Join([]string{"api", "key"}, "_") + " = " + secretValue
	directive := strings.Join([]string{"developer", "mode", "enabled"}, " ")
	personalValue := strings.Join([]string{"4773", "9182", "6405", "7399"}, ".")
	personalRecord := "payment card: " + personalValue
	withLocalPatternsRestored(t)
	if err := ApplyLocalPatternsOverride(&guardrail.LocalPatterns{
		Version:        1,
		Injection:      []string{directive},
		PIIDataRegexes: []string{`\b4\d{3}(?:\.\d{4}){3}\b`},
	}); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		direction string
		content   string
		category  string
		idPrefix  string
		sensitive string
	}{
		{name: "header", direction: "completion", content: header, category: CatCredentialLeak, idPrefix: "LP-SECRET-", sensitive: secretValue},
		{name: "assignment", direction: "completion", content: assignment, category: CatCredentialLeak, idPrefix: "LP-SECRET-", sensitive: secretValue},
		{name: "injection", direction: "prompt", content: directive, category: CatPromptInjection, idPrefix: "LP-INJ-", sensitive: directive},
		{name: "PII", direction: "completion", content: personalRecord, category: CatPIIExposure, idPrefix: "LP-PII-", sensitive: personalValue},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			verdict := scanLocalPatterns(tc.direction, tc.content)
			if verdict == nil || len(verdict.Findings) == 0 {
				t.Fatalf("scanLocalPatterns produced no finding: %#v", verdict)
			}
			normalized := NormalizeScanVerdict(verdict)
			var sensitive *NormalizedFinding
			for index := range normalized {
				if normalized[index].Category == tc.category && strings.HasPrefix(normalized[index].CanonicalID, tc.idPrefix) &&
					strings.Contains(normalized[index].Evidence, tc.sensitive) {
					sensitive = &normalized[index]
					break
				}
			}
			if sensitive == nil {
				t.Fatalf("actual local finding was not safely normalized: verdict=%#v normalized=%#v", verdict.Findings, normalized)
			}
			if strings.Contains(sensitive.CanonicalID, tc.sensitive) || strings.Contains(sensitive.OriginalID, tc.sensitive) ||
				strings.Contains(sensitive.Title, tc.sensitive) {
				t.Fatalf("normalized identity retained raw local value: %#v", *sensitive)
			}

			store, logger := testStoreAndLogger(t)
			inspectFindings := normalizedFindingsToInspect(normalized, verdict.Severity)
			_, scanID, err := logger.LogInspectFindingsWithCorrelation(t.Context(), scanner.InspectFindingSource{
				Scanner: "hook-rules", Target: "codex:PostToolUse", TargetType: "tool_response",
				Verdict: verdict.Action, Findings: inspectFindings,
			}, audit.ScanCorrelation{Connector: "codex"})
			if err != nil {
				t.Fatalf("persist normalized local finding: %v", err)
			}

			rows, err := store.ListScanFindings(scanID)
			if err != nil || len(rows) == 0 {
				t.Fatalf("persisted rows=%#v err=%v", rows, err)
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
				t.Fatalf("marshal canonical events: %v", err)
			}
			if strings.Contains(rawJSON, tc.sensitive) || strings.Contains(string(eventJSON), tc.sensitive) {
				t.Fatalf("raw local value survived raw_json/canonical persistence")
			}
			sum := sha256.Sum256([]byte(sensitive.Evidence))
			unkeyedFingerprint := hex.EncodeToString(sum[:])[:8]
			if strings.Contains(rawJSON, unkeyedFingerprint) || strings.Contains(string(eventJSON), unkeyedFingerprint) {
				t.Fatalf("local finding retained an unkeyed content fingerprint")
			}
			if !strings.Contains(rawJSON, `"content_fingerprint"`) {
				t.Fatalf("local finding lost keyed correlation fingerprint")
			}
			for _, row := range rows {
				fields := []string{row.RuleID.String, row.Category.String, row.Title.String, row.Description.String,
					row.EvidenceSummary.String, row.Location.String, row.Remediation.String, row.Tags.String}
				if strings.Contains(strings.Join(fields, " "), tc.sensitive) {
					t.Fatalf("raw local value survived scan_findings: %#v", row)
				}
			}
		})
	}
}

func TestLocalPatternCanonicalPrefixCannotSmuggleDirectiveIntoIdentity(t *testing.T) {
	directive := strings.Join([]string{"developer", "mode", "enabled"}, " ")
	raw := "TRUST-CUSTOM:" + directive
	verdict := &ScanVerdict{
		Scanner: "local-pattern", ScannerSources: []string{"local-pattern"},
		Severity: "HIGH", Action: "alert", Findings: []string{raw},
	}
	normalized := NormalizeScanVerdict(verdict)
	if len(normalized) != 1 || normalized[0].CanonicalID != "LP-INJ-MATCH" ||
		normalized[0].OriginalID != "LP-INJ-MATCH" || normalized[0].Category != CatPromptInjection ||
		normalized[0].Title != localInjectionFindingTitle {
		t.Fatalf("prefix-shaped directive became a finding identity: %#v", normalized)
	}

	store, logger := testStoreAndLogger(t)
	_, scanID, err := logger.LogInspectFindingsWithCorrelation(t.Context(), scanner.InspectFindingSource{
		Scanner: "hook-rules", Target: "codex:PostToolUse", TargetType: "tool_response",
		Verdict: verdict.Action, Findings: normalizedFindingsToInspect(normalized, verdict.Severity),
	}, audit.ScanCorrelation{Connector: "codex"})
	if err != nil {
		t.Fatal(err)
	}
	rawJSON, err := store.GetScanRawJSON(scanID)
	if err != nil {
		t.Fatal(err)
	}
	events, err := store.ListEvents(100)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := store.ListScanFindings(scanID)
	if err != nil || len(rows) != 1 {
		t.Fatalf("persisted prefix finding=%#v err=%v", rows, err)
	}
	persisted, err := json.Marshal(struct {
		RawJSON string
		Events  []audit.Event
		Rows    []audit.ScanFindingRow
	}{RawJSON: rawJSON, Events: events, Rows: rows})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(persisted), directive) || strings.Contains(string(persisted), raw) {
		t.Fatal("prefix-shaped directive crossed the forensic/canonical persistence boundary")
	}
	if rows[0].RuleID.String != "LP-INJ-MATCH" {
		t.Fatalf("persisted rule id=%q, want stable LP-INJ-MATCH", rows[0].RuleID.String)
	}
}
