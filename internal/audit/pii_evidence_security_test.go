// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
	"gopkg.in/yaml.v3"
)

func TestEnterprisePIIFallbackCatalogCoversPIIRules(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "policies", "guardrail", "*", "rules", "enterprise-data.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("enterprise PII policy fixtures are unavailable")
	}
	type catalogRule struct {
		ID   string   `yaml:"id"`
		Tags []string `yaml:"tags"`
	}
	var covered int
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		var catalog struct {
			Rules []catalogRule `yaml:"rules"`
		}
		if err := yaml.Unmarshal(raw, &catalog); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		for _, rule := range catalog.Rules {
			if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(rule.ID)), "ENT-") ||
				!hasExactFindingTag(rule.Tags, "pii") {
				continue
			}
			covered++
			if !isKnownEnterprisePIIFindingID(rule.ID) {
				t.Errorf("enterprise PII rule %q in %s is missing from bare-ID redaction fallback", rule.ID, path)
			}
		}
	}
	if covered == 0 {
		t.Fatal("enterprise PII catalog contained no tagged rules")
	}
}

func TestLogScanNeutralizesPIIValuesAcrossPersistenceSurfaces(t *testing.T) {
	logger := newTestLogger(t)
	runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(runtime)

	type piiCase struct {
		ruleID        string
		category      string
		tags          []string
		detectionOnly bool
	}
	cases := []piiCase{
		{ruleID: "PII-CUSTOM"},
		{ruleID: "CS-PII-CUSTOM"},
		{ruleID: "LP-PII-DATA", detectionOnly: true},
		{ruleID: "JUDGE-PII-CUSTOM"},
		{ruleID: "JUDGE-ADJ-PII"},
		{ruleID: "ENT-BULK-SSN"},
		{ruleID: "CUSTOM-PII-CATEGORY", category: "pii-exposure"},
		{ruleID: "CUSTOM-PII-TAG", tags: []string{"pii"}},
	}

	findings := make([]scanner.Finding, 0, len(cases))
	rawDigests := make(map[string]string, len(cases))
	keyedFingerprints := make(map[string]string, len(cases))
	rawValues := make(map[string]string, len(cases))
	for index, tc := range cases {
		// Build an SSN-shaped value at runtime. This validates the real
		// persistence boundary without placing a complete identifier in source.
		raw := strings.Join([]string{
			fmt.Sprintf("%03d", 710+index),
			fmt.Sprintf("%02d", 20+index),
			fmt.Sprintf("%04d", 8000+index),
		}, "-")
		rawValues[tc.ruleID] = raw
		keyedFingerprints[tc.ruleID] = testFindingContentFingerprint(t, runtime, raw)
		sum := sha256.Sum256([]byte(raw))
		rawDigests[tc.ruleID] = hex.EncodeToString(sum[:])[:8]
		decision, err := json.Marshal(map[string]string{"matched": raw})
		if err != nil {
			t.Fatal(err)
		}
		tags := append(append([]string(nil), tc.tags...), raw)
		if tc.detectionOnly {
			tags = append(tags, scanner.FindingTagDetectionOnly)
		}
		findings = append(findings, scanner.Finding{
			ID: raw, RuleID: tc.ruleID, Category: tc.category,
			Scanner: "hook-rules", Severity: scanner.SeverityHigh,
			Title: raw, Description: raw, EvidenceSummary: raw,
			Location: raw + "-location", Remediation: raw + "-remediation",
			ExternalEndpoint: raw + ".invalid", ContentFingerprint: raw,
			Tags: tags, DecisionPath: decision,
		})
	}

	result := &scanner.ScanResult{
		Scanner: "hook-rules", Target: "codex:PostToolUse", TargetType: "tool_response",
		Timestamp: time.Now().UTC(), Findings: findings,
	}
	corr := ScanCorrelation{
		EvaluationID: "pii-boundary-evaluation", SessionID: "pii-boundary-session",
		AgentInstanceID: "pii-boundary-agent", RequestID: "pii-boundary-request",
	}
	if err := logger.LogScanWithCorrelation(t.Context(), result, "alert", corr); err != nil {
		t.Fatalf("log PII findings: %v", err)
	}
	for index := range result.Findings {
		if result.Findings[index].ID != "" {
			t.Fatalf("PII finding %d retained producer ID %q", index, result.Findings[index].ID)
		}
		if result.Findings[index].FindingOccurrenceID == "" {
			t.Fatalf("PII finding %d lost canonical occurrence ID", index)
		}
	}

	rows, err := logger.store.db.Query(`
SELECT rule_id, title, severity, description, evidence_summary, location,
       remediation, tags, content_fingerprint, external_endpoint, decision_path,
       evaluation_id, session_id, agent_instance_id
FROM scan_findings WHERE scan_id = ?`, result.ScanID)
	if err != nil {
		t.Fatalf("query PII findings: %v", err)
	}
	defer rows.Close()
	seen := make(map[string]bool, len(cases))
	for rows.Next() {
		var (
			ruleID, title, severity, tags            string
			evaluationID, sessionID, agentInstanceID string
			description, evidence, location          sql.NullString
			remediation, endpoint, decision          sql.NullString
			fingerprint                              sql.NullString
		)
		if err := rows.Scan(
			&ruleID, &title, &severity, &description, &evidence, &location,
			&remediation, &tags, &fingerprint, &endpoint, &decision,
			&evaluationID, &sessionID, &agentInstanceID,
		); err != nil {
			t.Fatalf("scan PII finding: %v", err)
		}
		raw, ok := rawValues[ruleID]
		if !ok {
			t.Fatalf("unexpected PII rule %q", ruleID)
		}
		seen[ruleID] = true
		if title != redactedPIIFindingTitle || severity != string(scanner.SeverityHigh) ||
			!fingerprint.Valid || fingerprint.String != keyedFingerprints[ruleID] ||
			evaluationID != corr.EvaluationID ||
			sessionID != corr.SessionID || agentInstanceID != corr.AgentInstanceID {
			t.Fatalf("PII metadata changed for %s: title=%q severity=%q fingerprint=%#v evaluation=%q session=%q agent=%q",
				ruleID, title, severity, fingerprint, evaluationID, sessionID, agentInstanceID)
		}
		wantTags := `["pii","redacted"]`
		if ruleID == "LP-PII-DATA" {
			wantTags = `["pii","detection-only","redacted"]`
		}
		if tags != wantTags {
			t.Fatalf("%s tags=%s, want %s", ruleID, tags, wantTags)
		}
		for field, value := range map[string]string{
			"description": description.String, "evidence": evidence.String,
			"location": location.String, "remediation": remediation.String,
			"tags": tags, "endpoint": endpoint.String, "decision": decision.String,
		} {
			if strings.Contains(value, raw) {
				t.Fatalf("%s %s retained raw PII", ruleID, field)
			}
			if strings.Contains(value, rawDigests[ruleID]) || strings.Contains(value, "sha=") {
				t.Fatalf("%s %s retained enumerable PII digest", ruleID, field)
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(seen) != len(cases) {
		t.Fatalf("persisted classified PII=%v, want all %d cases", seen, len(cases))
	}

	rawJSON, err := logger.store.GetScanRawJSON(result.ScanID)
	if err != nil {
		t.Fatalf("GetScanRawJSON: %v", err)
	}
	_, records := runtime.snapshot()
	for _, raw := range rawValues {
		if strings.Contains(rawJSON, raw) {
			t.Fatal("scan_results.raw_json retained raw PII")
		}
		for _, record := range records {
			for field, value := range securityActionBody(t, record) {
				if strings.Contains(valueAsText(value), raw) {
					t.Fatalf("canonical record field %q retained raw PII", field)
				}
			}
		}
	}
	for _, digest := range rawDigests {
		if strings.Contains(rawJSON, digest) || strings.Contains(rawJSON, "sha=") {
			t.Fatal("scan_results.raw_json retained enumerable PII digest")
		}
		for _, record := range records {
			for field, value := range securityActionBody(t, record) {
				text := valueAsText(value)
				if strings.Contains(text, digest) || strings.Contains(text, "sha=") {
					t.Fatalf("canonical record field %q retained enumerable PII digest", field)
				}
			}
		}
	}
}

func TestRedactPersistedPIIFindingIsIdempotent(t *testing.T) {
	raw := strings.Join([]string{"private", "person", strings.Repeat("x", 16)}, "-")
	decision, err := json.Marshal(map[string]string{"matched": raw})
	if err != nil {
		t.Fatal(err)
	}
	finding := scanner.Finding{
		ID: "LP-PII-DATA-source", RuleID: "LP-PII-DATA", Category: "pii-exposure",
		Severity: scanner.SeverityHigh, Title: raw, Description: raw,
		EvidenceSummary: raw, Location: raw, Remediation: raw, ExternalEndpoint: raw,
		ContentFingerprint: raw, Tags: []string{"pii", scanner.FindingTagDetectionOnly, raw},
		DecisionPath: decision,
	}
	redactPersistedPIIFinding(&finding)
	first := finding
	first.Tags = append([]string(nil), finding.Tags...)
	first.DecisionPath = append(json.RawMessage(nil), finding.DecisionPath...)
	redactPersistedPIIFinding(&finding)
	if !reflect.DeepEqual(finding, first) {
		t.Fatalf("second PII redaction changed canonical placeholder: first=%#v second=%#v", first, finding)
	}
}
