// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// GAP-2435 (p0 GAP-0575): a judged skill scan's persisted scan and
// scan-finding rows name the judge model. The watcher set it only on the
// legacy event text, which the stored row never kept, so an exported
// Windows managed row could not show that the judge ran.
func TestGAP2435JudgedScanRowsNameTheJudgeModel(t *testing.T) {
	fixture, api, _ := newCLIObservabilityV8Fixture(t)
	const model = "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0"
	result := func(judge string) *scanner.ScanResult {
		return &scanner.ScanResult{
			Scanner: "skill-scanner", Target: "ra35-notes", TargetType: "skill",
			Timestamp: time.Now().UTC(), Duration: 2 * time.Second, JudgeModel: judge,
			Findings: []scanner.Finding{{
				ID: "f-1", RuleID: "LLM_DATA_EXFILTRATION", Severity: scanner.SeverityHigh,
				Title: "Unauthorized credential exfiltration", Description: "hidden instruction",
				Location: "SKILL.md", Scanner: "skill-scanner",
			}},
		}
	}
	judged := result(model)
	if err := api.logger.LogScanWithCorrelation(t.Context(), judged, "block",
		audit.ScanCorrelation{RunID: "gap-2435-judged", JudgeModel: model}); err != nil {
		t.Fatal(err)
	}
	if err := api.logger.LogScanWithCorrelation(t.Context(), result(""), "block",
		audit.ScanCorrelation{RunID: "gap-2435-plain"}); err != nil {
		t.Fatal(err)
	}
	database, err := sql.Open("sqlite", fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	row := func(runID, event string) (string, string) {
		t.Helper()
		var details, payload string
		if err := database.QueryRow("SELECT COALESCE(details,''), COALESCE(payload_json,'') FROM audit_events "+
			"WHERE run_id = ? AND event_name = ?", runID, event).Scan(&details, &payload); err != nil {
			t.Fatalf("%s %s: %v", runID, event, err)
		}
		return details, payload
	}
	wantModel := "\"gen_ai.request.model\":\"" + model + "\""
	details, payload := row("gap-2435-judged", "scan.completed")
	if !strings.Contains(details, "judge="+model) || !strings.Contains(payload, wantModel) {
		t.Fatalf("judged scan row details=%q payload=%q, want the judge model", details, payload)
	}
	if _, payload := row("gap-2435-judged", "finding.observed"); !strings.Contains(payload, wantModel) {
		t.Fatalf("judged finding row payload=%q, want the judge model", payload)
	}
	details, payload = row("gap-2435-plain", "scan.completed")
	if strings.Contains(details, "judge=") || strings.Contains(payload, "gen_ai.request.model") {
		t.Fatalf("a scan without a judge names one: details=%q payload=%q", details, payload)
	}
}

func TestGAP2435APIScanCorrelationCarriesTheJudgeModel(t *testing.T) {
	corr := scanCorrelationWithJudge(t.Context(), &scanner.ScanResult{JudgeModel: "bedrock/haiku"})
	if corr.JudgeModel != "bedrock/haiku" {
		t.Fatalf("API scan correlation judge = %q, want bedrock/haiku", corr.JudgeModel)
	}
	if corr := scanCorrelationWithJudge(t.Context(), nil); corr.JudgeModel != "" {
		t.Fatalf("nil result judge = %q", corr.JudgeModel)
	}
}
