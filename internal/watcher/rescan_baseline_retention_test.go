// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// TestFindingDriftSurvivesRetentionOfTheBaselineScan: retention deleted the
// scan a target_snapshots baseline pointed at, so the rescan after a scanner
// change logged "findingDrift: load baseline scan ...: sql: no rows" and
// reported no new finding and no severity escalation (rel-1-0-10:GAP-1177).
// Retention keeps a baseline's scan, so the drift is computed.
func TestFindingDriftSurvivesRetentionOfTheBaselineScan(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	target := filepath.Join(skillDir, "gap1177")
	old := time.Now().UTC().Add(-100 * 24 * time.Hour)
	prev := scanner.ScanResult{Scanner: "skill-scanner", Target: target, Timestamp: old,
		Findings: []scanner.Finding{{ID: "f1", Severity: scanner.SeverityLow, Title: "low finding", Scanner: "skill-scanner"}}}
	raw, err := json.Marshal(prev)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.InsertScanResult("gap1177-baseline", "skill-scanner", target, old, 1, 1, "LOW", string(raw)); err != nil {
		t.Fatal(err)
	}
	if err := store.SetTargetSnapshot(string(InstallSkill), target, "h", "{}", "{}", "[]", "gap1177-baseline", "old-fp"); err != nil {
		t.Fatal(err)
	}
	judge, err := audit.NewJudgeBodyStore(filepath.Join(cfg.DataDir, "judge_bodies.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = judge.Close() })
	reaper, err := audit.NewRetentionReaper(store, judge, 90, audit.RetentionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reaper.Run(t.Context()); err != nil {
		t.Fatal(err)
	}

	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)
	baseline, err := store.GetTargetSnapshot(string(InstallSkill), target)
	if err != nil {
		t.Fatal(err)
	}
	current := &scanner.ScanResult{Scanner: "skill-scanner", Target: target, Timestamp: time.Now().UTC(),
		Findings: []scanner.Finding{
			{ID: "f1", Severity: scanner.SeverityLow, Title: "low finding", Scanner: "skill-scanner"},
			{ID: "f2", Severity: scanner.SeverityHigh, Title: "new high finding", Scanner: "skill-scanner"},
		}}
	deltas := w.findingDrift(baseline, current)
	var newFinding, escalation bool
	for _, d := range deltas {
		newFinding = newFinding || d.Type == DriftNewFinding
		escalation = escalation || d.Type == DriftSeverityChange
	}
	if !newFinding || !escalation {
		t.Fatalf("drift after retention = %+v, want a new finding and a severity escalation", deltas)
	}
}

// TestFindingDriftNamesABaselineScanThatIsGone: a baseline whose scan an
// earlier build's retention, or an evidence purge, removed gets one line that
// says so and that the new scan becomes the baseline, not the raw
// "sql: no rows" error (rel-1-0-10:GAP-1177).
func TestFindingDriftNamesABaselineScanThatIsGone(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	target := filepath.Join(skillDir, "gap1177-gone")
	if err := store.SetTargetSnapshot(string(InstallSkill), target, "h", "{}", "{}", "[]", "gap1177-gone-scan", "old-fp"); err != nil {
		t.Fatal(err)
	}
	baseline, err := store.GetTargetSnapshot(string(InstallSkill), target)
	if err != nil {
		t.Fatal(err)
	}
	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)
	current := &scanner.ScanResult{Scanner: "skill-scanner", Target: target, Timestamp: time.Now().UTC(),
		Findings: []scanner.Finding{{ID: "f2", Severity: scanner.SeverityHigh, Title: "high finding", Scanner: "skill-scanner"}}}

	r, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = wr
	deltas := w.findingDrift(baseline, current)
	os.Stderr = orig
	_ = wr.Close()
	out, _ := io.ReadAll(r)

	if len(deltas) != 0 {
		t.Fatalf("deltas = %+v, want none without an earlier scan", deltas)
	}
	log := string(out)
	if strings.Contains(log, "sql: no rows") ||
		!strings.Contains(log, "gap1177-gone-scan") ||
		!strings.Contains(log, "no longer in the audit store") ||
		!strings.Contains(log, "becomes the baseline") {
		t.Fatalf("log = %q, want one line naming the missing baseline scan and the re-baseline", log)
	}
}
