// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

func emitFindingLifecycleScan(
	t *testing.T,
	store *Store,
	result *scanner.ScanResult,
	agent scanner.AgentIdentity,
) string {
	t.Helper()
	scanID, err := scanner.EmitScanResult(context.Background(), store, result, agent)
	if err != nil {
		t.Fatalf("EmitScanResult: %v", err)
	}
	return scanID
}

func lifecycleFinding(evidence string, severity scanner.Severity) scanner.Finding {
	line := 7
	return scanner.Finding{
		Scanner: "codeguard", RuleID: "CG-LIFECYCLE", Severity: severity,
		Title: "Lifecycle finding", Description: "presentation", EvidenceSummary: evidence,
		Location: `C:\repo\main.go:7`, LineNumber: &line, Tags: []string{"code"},
	}
}

func lifecycleResult(at time.Time, findings ...scanner.Finding) *scanner.ScanResult {
	return &scanner.ScanResult{
		Scanner: "codeguard", Target: `C:\repo`, TargetType: "code", Timestamp: at,
		Duration: time.Millisecond, Findings: findings,
	}
}

func TestFindingLifecycleMigrationCreatesIdentityProjection(t *testing.T) {
	store := newTestLogger(t).store
	if present, err := store.hasColumn("scan_findings", "finding_fingerprint"); err != nil || !present {
		t.Fatalf("scan occurrence fingerprint column present=%t err=%v", present, err)
	}
	for _, object := range []struct {
		kind string
		name string
	}{
		{kind: "table", name: "finding_scopes"},
		{kind: "table", name: "finding_states"},
		{kind: "index", name: "idx_scan_findings_finding_fingerprint"},
		{kind: "index", name: "idx_finding_states_scope_state"},
		{kind: "index", name: "idx_finding_states_resolved_at"},
	} {
		var count int
		if err := store.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type=? AND name=?`,
			object.kind, object.name).Scan(&count); err != nil || count != 1 {
			t.Errorf("migration object %s/%s count=%d err=%v", object.kind, object.name, count, err)
		}
	}
}

func TestFindingLifecycleCompactsRepeatedStaticStorageAndDeduplicatesCurrentState(t *testing.T) {
	store := newTestLogger(t).store
	base := time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC)
	first := lifecycleResult(base, lifecycleFinding("same matched bytes", scanner.SeverityHigh))
	firstScanID := emitFindingLifecycleScan(t, store, first, scanner.AgentIdentity{})
	if first.FindingLifecycle == nil || !first.FindingLifecycle.Managed ||
		len(first.FindingLifecycle.Observations) != 1 ||
		first.FindingLifecycle.Observations[0].Status != scanner.FindingLifecycleNew ||
		first.FindingLifecycle.GaugeDelta[scanner.SeverityHigh] != 1 {
		t.Fatalf("first lifecycle delta=%+v", first.FindingLifecycle)
	}

	second := lifecycleResult(base.Add(time.Minute), lifecycleFinding("same matched bytes", scanner.SeverityHigh))
	secondScanID := emitFindingLifecycleScan(t, store, second, scanner.AgentIdentity{})
	if second.FindingLifecycle == nil || len(second.FindingLifecycle.Observations) != 1 ||
		second.FindingLifecycle.Observations[0].Status != scanner.FindingLifecycleRepeated ||
		len(second.FindingLifecycle.GaugeDelta) != 0 {
		t.Fatalf("repeat lifecycle delta=%+v", second.FindingLifecycle)
	}
	lastScanID := secondScanID
	for scanNumber := 3; scanNumber <= 263; scanNumber++ {
		repeated := lifecycleResult(
			base.Add(time.Duration(scanNumber-1)*time.Minute),
			lifecycleFinding("same matched bytes", scanner.SeverityHigh),
		)
		lastScanID = emitFindingLifecycleScan(t, store, repeated, scanner.AgentIdentity{})
		if got := repeated.FindingLifecycle; got == nil || len(got.Observations) != 1 ||
			got.Observations[0].Status != scanner.FindingLifecycleRepeated {
			t.Fatalf("repeat %d lifecycle delta=%+v", scanNumber, got)
		}
	}

	states, err := store.ListFindingStates("codeguard", `C:\repo`, false, 10)
	if err != nil || len(states) != 1 {
		t.Fatalf("active distinct states=%+v err=%v", states, err)
	}
	if states[0].OccurrenceCount != 263 || states[0].FirstSeen != base ||
		states[0].LastSeen != base.Add(262*time.Minute) || states[0].FirstScanID != firstScanID ||
		states[0].LastScanID != lastScanID || states[0].State != findingStateActive {
		t.Fatalf("deduplicated state=%+v", states[0])
	}
	if states[0].LastOccurrenceID != first.Findings[0].FindingOccurrenceID ||
		first.Findings[0].FindingOccurrenceID == second.Findings[0].FindingOccurrenceID {
		t.Fatalf("transition/repeat identities mismatch: first=%q second=%q state=%q",
			first.Findings[0].FindingOccurrenceID, second.Findings[0].FindingOccurrenceID,
			states[0].LastOccurrenceID)
	}
	firstRows, listErr := store.ListScanFindings(firstScanID)
	if listErr != nil || len(firstRows) != 1 || !firstRows[0].FindingFingerprint.Valid ||
		firstRows[0].FindingFingerprint.String != states[0].Fingerprint {
		t.Fatalf("first transition rows=%+v err=%v", firstRows, listErr)
	}
	secondRows, listErr := store.ListScanFindings(secondScanID)
	if listErr != nil || len(secondRows) != 0 {
		t.Fatalf("repeat scan added detail rows=%+v err=%v", secondRows, listErr)
	}
	var detailCount int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM scan_findings`).Scan(&detailCount); err != nil || detailCount != 1 {
		t.Fatalf("static transition detail count=%d err=%v", detailCount, err)
	}
}

func TestQueryFindingStatesDefaultsCurrentAndSupportsSinceAndNewOnly(t *testing.T) {
	store := newTestLogger(t).store
	base := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	first := lifecycleFinding("first bytes", scanner.SeverityHigh)
	first.RuleID = "CG-FIRST"
	emitFindingLifecycleScan(t, store, lifecycleResult(base, first), scanner.AgentIdentity{})

	second := lifecycleFinding("second bytes", scanner.SeverityMedium)
	second.RuleID = "CG-SECOND"
	emitFindingLifecycleScan(t, store, lifecycleResult(base.Add(time.Hour), first, second), scanner.AgentIdentity{})
	emitFindingLifecycleScan(t, store, lifecycleResult(base.Add(2*time.Hour), second), scanner.AgentIdentity{})

	current, err := store.QueryFindingStates(FindingStateQuery{})
	if err != nil || len(current) != 1 || current[0].RuleID != "CG-SECOND" || current[0].State != findingStateActive {
		t.Fatalf("default current state=%+v err=%v", current, err)
	}
	cutoff := base.Add(30 * time.Minute)
	changed, err := store.QueryFindingStates(FindingStateQuery{
		IncludeResolved: true, Since: &cutoff, Limit: 10,
	})
	if err != nil || len(changed) != 2 {
		t.Fatalf("states changed since cutoff=%+v err=%v", changed, err)
	}
	total, err := store.CountFindingStates(FindingStateQuery{
		IncludeResolved: true, Since: &cutoff, Limit: 1,
	})
	if err != nil || total != 2 {
		t.Fatalf("distinct total ignoring page limit=%d err=%v", total, err)
	}
	limited, err := store.QueryFindingStates(FindingStateQuery{
		IncludeResolved: true, Since: &cutoff, Limit: 1,
	})
	if err != nil || len(limited) != 1 {
		t.Fatalf("bounded distinct page=%+v err=%v", limited, err)
	}
	snapshotRows, snapshotCount, err := store.QueryFindingStatesWithCount(
		context.Background(),
		FindingStateQuery{IncludeResolved: true, Since: &cutoff, Limit: 1},
	)
	if err != nil || len(snapshotRows) != 1 || snapshotCount != 2 {
		t.Fatalf("snapshot page=%+v count=%d err=%v", snapshotRows, snapshotCount, err)
	}
	newOnly, err := store.QueryFindingStates(FindingStateQuery{
		IncludeResolved: true, Since: &cutoff, NewOnly: true, Limit: 10,
	})
	if err != nil || len(newOnly) != 1 || newOnly[0].RuleID != "CG-SECOND" {
		t.Fatalf("new states since cutoff=%+v err=%v", newOnly, err)
	}
	lateCutoff := base.Add(90 * time.Minute)
	resolvedDelta, err := store.QueryFindingStates(FindingStateQuery{
		IncludeResolved: true, Since: &lateCutoff, Limit: 10,
	})
	if err != nil || len(resolvedDelta) != 2 {
		t.Fatalf("last-seen/resolution delta=%+v err=%v", resolvedDelta, err)
	}
}

func TestFindingLifecycleResolvesChangesEmptyScansAndReopens(t *testing.T) {
	store := newTestLogger(t).store
	base := time.Date(2026, 8, 2, 10, 0, 0, 0, time.UTC)
	original := lifecycleResult(base, lifecycleFinding("original bytes", scanner.SeverityHigh))
	emitFindingLifecycleScan(t, store, original, scanner.AgentIdentity{})

	changed := lifecycleResult(base.Add(time.Minute), lifecycleFinding("changed bytes", scanner.SeverityHigh))
	emitFindingLifecycleScan(t, store, changed, scanner.AgentIdentity{})
	if got := changed.FindingLifecycle; got == nil || len(got.Observations) != 1 ||
		got.Observations[0].Status != scanner.FindingLifecycleNew || len(got.Resolved) != 1 {
		t.Fatalf("content-change delta=%+v", got)
	}
	all, err := store.ListFindingStates("codeguard", `C:\repo`, true, 10)
	if err != nil || len(all) != 2 {
		t.Fatalf("content-addressed history=%+v err=%v", all, err)
	}

	empty := lifecycleResult(base.Add(2 * time.Minute))
	emitFindingLifecycleScan(t, store, empty, scanner.AgentIdentity{})
	if got := empty.FindingLifecycle; got == nil || len(got.Resolved) != 1 ||
		got.GaugeDelta[scanner.SeverityHigh] != -1 {
		t.Fatalf("empty-scan resolution=%+v", got)
	}
	active, err := store.ListFindingStates("codeguard", `C:\repo`, false, 10)
	if err != nil || len(active) != 0 {
		t.Fatalf("active states after complete empty scan=%+v err=%v", active, err)
	}

	reopened := lifecycleResult(base.Add(3*time.Minute), lifecycleFinding("changed bytes", scanner.SeverityHigh))
	emitFindingLifecycleScan(t, store, reopened, scanner.AgentIdentity{})
	if got := reopened.FindingLifecycle; got == nil || len(got.Observations) != 1 ||
		got.Observations[0].Status != scanner.FindingLifecycleReopened ||
		got.GaugeDelta[scanner.SeverityHigh] != 1 {
		t.Fatalf("reopen delta=%+v", got)
	}
	active, err = store.ListFindingStates("codeguard", `C:\repo`, false, 10)
	if err != nil || len(active) != 1 || active[0].OccurrenceCount != 2 || active[0].ResolvedAt != nil {
		t.Fatalf("reopened state=%+v err=%v", active, err)
	}
}

func TestFindingLifecycleSeverityUpdateAndOutOfOrderScan(t *testing.T) {
	store := newTestLogger(t).store
	base := time.Date(2026, 8, 3, 10, 0, 0, 0, time.UTC)
	current := lifecycleResult(base.Add(2*time.Minute),
		lifecycleFinding("same bytes", scanner.SeverityHigh),
		lifecycleFinding("second bytes", scanner.SeverityMedium),
	)
	current.Findings[1].RuleID = "CG-SECOND"
	emitFindingLifecycleScan(t, store, current, scanner.AgentIdentity{})

	older := lifecycleResult(base, lifecycleFinding("same bytes", scanner.SeverityLow))
	emitFindingLifecycleScan(t, store, older, scanner.AgentIdentity{})
	if got := older.FindingLifecycle; got == nil || len(got.Resolved) != 0 ||
		len(got.Observations) != 1 || got.Observations[0].Status != scanner.FindingLifecycleRepeated {
		t.Fatalf("out-of-order delta=%+v", got)
	}
	active, err := store.ListFindingStates("codeguard", `C:\repo`, false, 10)
	if err != nil || len(active) != 2 {
		t.Fatalf("out-of-order active states=%+v err=%v", active, err)
	}
	for _, state := range active {
		if state.RuleID == "CG-LIFECYCLE" &&
			(state.Severity != string(scanner.SeverityHigh) || state.FirstSeen != base ||
				state.LastSeen != base.Add(2*time.Minute) || state.OccurrenceCount != 2) {
			t.Fatalf("out-of-order scan overwrote current state: %+v", state)
		}
		if state.State != findingStateActive {
			t.Fatalf("out-of-order scan resolved current state: %+v", state)
		}
	}

	updated := lifecycleResult(base.Add(3*time.Minute), lifecycleFinding("same bytes", scanner.SeverityCritical))
	emitFindingLifecycleScan(t, store, updated, scanner.AgentIdentity{})
	if got := updated.FindingLifecycle; got == nil || len(got.Observations) != 1 ||
		got.Observations[0].Status != scanner.FindingLifecycleUpdated ||
		got.GaugeDelta[scanner.SeverityHigh] != -1 ||
		got.GaugeDelta[scanner.SeverityCritical] != 1 || len(got.Resolved) != 1 {
		t.Fatalf("severity update delta=%+v", got)
	}
}

func TestFindingLifecycleFailedAndRuntimeScansDoNotMutateCurrentState(t *testing.T) {
	store := newTestLogger(t).store
	base := time.Date(2026, 8, 4, 10, 0, 0, 0, time.UTC)
	initial := lifecycleResult(base, lifecycleFinding("same bytes", scanner.SeverityHigh))
	emitFindingLifecycleScan(t, store, initial, scanner.AgentIdentity{})

	failed := lifecycleResult(base.Add(time.Minute))
	failed.ExitCode = 2
	failed.ScanError = "scanner failed"
	emitFindingLifecycleScan(t, store, failed, scanner.AgentIdentity{})
	if failed.FindingLifecycle == nil || failed.FindingLifecycle.Managed {
		t.Fatalf("failed scan entered lifecycle=%+v", failed.FindingLifecycle)
	}
	active, err := store.ListFindingStates("codeguard", `C:\repo`, false, 10)
	if err != nil || len(active) != 1 || active[0].OccurrenceCount != 1 {
		t.Fatalf("failed scan changed current state=%+v err=%v", active, err)
	}

	for i := 0; i < 2; i++ {
		runtime := &scanner.ScanResult{
			Scanner: "hook-rules", Target: "codex:PreToolUse", TargetType: "tool_call",
			Timestamp: base.Add(time.Duration(i+2) * time.Minute),
			Findings: []scanner.Finding{{
				Scanner: "hook-rules", RuleID: "RUNTIME-RULE", Severity: scanner.SeverityHigh,
				EvidenceSummary: "same runtime bytes",
			}},
		}
		emitFindingLifecycleScan(t, store, runtime, scanner.AgentIdentity{EvaluationID: "runtime-evaluation"})
		if runtime.FindingLifecycle == nil || runtime.FindingLifecycle.Managed {
			t.Fatalf("runtime occurrence entered lifecycle=%+v", runtime.FindingLifecycle)
		}
	}
	misclassifiedRuntime := &scanner.ScanResult{
		Scanner: "hook-rules", Target: "runtime-target", TargetType: "file",
		Timestamp: base.Add(4 * time.Minute),
		Findings:  []scanner.Finding{lifecycleFinding("runtime bytes", scanner.SeverityHigh)},
	}
	emitFindingLifecycleScan(t, store, misclassifiedRuntime, scanner.AgentIdentity{})
	if misclassifiedRuntime.FindingLifecycle == nil || misclassifiedRuntime.FindingLifecycle.Managed {
		t.Fatalf("runtime scanner name was overridden by asset-looking target type: %+v",
			misclassifiedRuntime.FindingLifecycle)
	}
	var runtimeOccurrences int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM scan_findings WHERE evaluation_id = ?`,
		"runtime-evaluation").Scan(&runtimeOccurrences); err != nil || runtimeOccurrences != 2 {
		t.Fatalf("runtime occurrences=%d err=%v", runtimeOccurrences, err)
	}
	var runtimeStates int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM finding_states WHERE scope_scanner='hook-rules'`).Scan(&runtimeStates); err != nil || runtimeStates != 0 {
		t.Fatalf("runtime distinct states=%d err=%v", runtimeStates, err)
	}
}

func TestFindingLifecyclePersistenceRollsBackAllRowsOnStateFailure(t *testing.T) {
	store := newTestLogger(t).store
	base := time.Date(2026, 8, 5, 10, 0, 0, 0, time.UTC)
	initial := lifecycleResult(base, lifecycleFinding("same bytes", scanner.SeverityHigh))
	emitFindingLifecycleScan(t, store, initial, scanner.AgentIdentity{})
	if _, err := store.db.Exec(`CREATE TRIGGER reject_finding_state_update
		BEFORE UPDATE ON finding_states BEGIN SELECT RAISE(ABORT, 'state update rejected'); END`); err != nil {
		t.Fatal(err)
	}
	repeated := lifecycleResult(base.Add(time.Minute), lifecycleFinding("same bytes", scanner.SeverityHigh))
	_, err := scanner.EmitScanResult(context.Background(), store, repeated, scanner.AgentIdentity{})
	if err == nil || !strings.Contains(err.Error(), "state update rejected") {
		t.Fatalf("state failure was not returned: %v", err)
	}
	for table, want := range map[string]int{"scan_results": 1, "scan_findings": 1, "finding_states": 1} {
		var got int
		if queryErr := store.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&got); queryErr != nil || got != want {
			t.Errorf("atomic rollback %s count=%d want=%d err=%v", table, got, want, queryErr)
		}
	}
	states, err := store.ListFindingStates("codeguard", `C:\repo`, false, 10)
	if err != nil || len(states) != 1 || states[0].OccurrenceCount != 1 {
		t.Fatalf("state changed after rollback=%+v err=%v", states, err)
	}
}

func TestFindingLifecycleStateSurvivesOccurrenceRetention(t *testing.T) {
	store, judge := newRetentionStores(t)
	now := time.Date(2026, 8, 6, 10, 0, 0, 0, time.UTC)
	result := lifecycleResult(now.Add(-60*24*time.Hour), lifecycleFinding("retained state", scanner.SeverityHigh))
	emitFindingLifecycleScan(t, store, result, scanner.AgentIdentity{})
	reaper := newRetentionReaperAt(t, store, judge, 30, now, RetentionOptions{}, retentionHooks{})
	if _, err := reaper.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"scan_results", "scan_findings"} {
		var count int
		if err := store.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&count); err != nil || count != 0 {
			t.Errorf("retained occurrence table %s count=%d err=%v", table, count, err)
		}
	}
	states, err := store.ListFindingStates("codeguard", `C:\repo`, false, 10)
	if err != nil || len(states) != 1 || states[0].State != findingStateActive {
		t.Fatalf("protected current state=%+v err=%v", states, err)
	}
}
