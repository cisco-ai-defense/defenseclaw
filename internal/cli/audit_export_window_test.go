// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// auditWindowTestDatabase stores one connector-hook row per timestamp, in
// the given (not necessarily chronological) insertion order, and returns
// the database path. Row ids are "row-<n>" by position.
func auditWindowTestDatabase(t *testing.T, timestamps ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE audit_events (
		id TEXT, timestamp TEXT, action TEXT, target TEXT, actor TEXT,
		details TEXT, structured_json TEXT, severity TEXT, run_id TEXT,
		session_id TEXT, trace_id TEXT, agent_id TEXT, agent_name TEXT,
		agent_instance_id TEXT, sidecar_instance_id TEXT, schema_version INTEGER,
		content_hash TEXT, generation INTEGER, binary_version TEXT,
		destination_app TEXT, tool_name TEXT, tool_id TEXT, policy_id TEXT,
		connector TEXT)`); err != nil {
		t.Fatal(err)
	}
	for index, stamp := range timestamps {
		if _, err := db.Exec(
			`INSERT INTO audit_events (id,timestamp,action,actor,details,severity,schema_version,generation,connector)
			 VALUES (?,?,?,?,?,?,?,?,?)`,
			"row-"+string(rune('0'+index)), stamp, string(audit.ActionConnectorHook), "defenseclaw",
			"connector=claudecode", "INFO", 7, 0, "claudecode",
		); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

// runAuditExportForTest exports path with the given flag values and
// returns the exported row ids in output order.
func runAuditExportForTest(t *testing.T, path string, limit int, newest bool, since, until string) ([]string, error) {
	t.Helper()
	previousConfig := cfg
	previous := []any{auditExportOut, auditExportConnector, auditExportLimit, auditExportIncludeActivity, auditExportSince, auditExportUntil, auditExportNewest}
	t.Cleanup(func() {
		cfg = previousConfig
		auditExportOut, auditExportConnector, auditExportLimit = previous[0].(string), previous[1].(string), previous[2].(int)
		auditExportIncludeActivity, auditExportSince, auditExportUntil = previous[3].(bool), previous[4].(string), previous[5].(string)
		auditExportNewest = previous[6].(bool)
	})
	cfg = &config.Config{AuditDB: path}
	auditExportOut = filepath.Join(t.TempDir(), "out.jsonl")
	auditExportConnector, auditExportIncludeActivity = "", false
	auditExportLimit, auditExportNewest, auditExportSince, auditExportUntil = limit, newest, since, until
	if err := runAuditExport(nil, nil); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(auditExportOut)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("line is not JSON: %v\n%s", err, line)
		}
		id, _ := event["id"].(string)
		ids = append(ids, id)
	}
	return ids, nil
}

// --limit keeps the oldest rows; --newest keeps the most recent ones, still
// written oldest first. An administrator asking for recent events used to
// get rows from hours earlier.
func TestRunAuditExportNewestKeepsTheMostRecentRows(t *testing.T) {
	path := auditWindowTestDatabase(t,
		"2026-09-27T15:53:00Z", "2026-09-27T18:40:00Z", "2026-09-27T16:10:00Z",
		"2026-09-27T18:34:30.5Z", "2026-09-27T17:00:00Z",
	)
	oldest, err := runAuditExportForTest(t, path, 2, false, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(oldest, ",") != "row-0,row-2" {
		t.Fatalf("--limit 2 = %v, want the two oldest rows row-0,row-2", oldest)
	}
	newest, err := runAuditExportForTest(t, path, 2, true, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(newest, ",") != "row-3,row-1" {
		t.Fatalf("--limit 2 --newest = %v, want row-3,row-1 (newest two, oldest first)", newest)
	}
	all, err := runAuditExportForTest(t, path, 0, true, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(all, ",") != "row-0,row-2,row-4,row-3,row-1" {
		t.Fatalf("--newest without --limit = %v, want every row oldest first", all)
	}
}

// --since and --until select an exact window across the stored timestamp
// formats (fractional seconds, SQLite's space form, an offset).
func TestRunAuditExportSinceUntilSelectAWindow(t *testing.T) {
	path := auditWindowTestDatabase(t,
		"2026-09-27T18:29:59.999Z",     // row-0: just before
		"2026-09-27T18:30:00Z",         // row-1: the --since instant
		"2026-09-27 18:45:00",          // row-2: SQLite form, inside
		"2026-09-27T20:50:00+02:00",    // row-3: 18:50Z, inside
		"2026-09-27T19:00:00Z",         // row-4: the --until instant, excluded
		"2026-09-26T18:40:00Z",         // row-5: a day earlier
		"not a timestamp",              // row-6: unparseable
		"2026-09-27T18:59:59.9999999Z", // row-7: inside
	)
	ids, err := runAuditExportForTest(t, path, 0, false, "2026-09-27T18:30:00Z", "2026-09-27T19:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, id := range ids {
		got[id] = true
	}
	for _, want := range []string{"row-1", "row-2", "row-3", "row-7"} {
		if !got[want] {
			t.Errorf("window export %v is missing %s", ids, want)
		}
	}
	for _, unwanted := range []string{"row-0", "row-4", "row-5", "row-6"} {
		if got[unwanted] {
			t.Errorf("window export %v includes %s", ids, unwanted)
		}
	}
	limited, err := runAuditExportForTest(t, path, 1, true, "2026-09-27T18:30:00Z", "2026-09-27T19:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(limited, ",") != "row-7" {
		t.Fatalf("--limit 1 --newest in the window = %v, want row-7", limited)
	}

	// A relative --since counts back from now; an unknown value, a
	// negative duration or an empty window is refused.
	now := time.Date(2026, 9, 27, 19, 0, 0, 0, time.UTC)
	previous := []string{auditExportSince, auditExportUntil}
	t.Cleanup(func() { auditExportSince, auditExportUntil = previous[0], previous[1] })
	auditExportSince, auditExportUntil = "30m", ""
	window, err := parseAuditExportWindow(now)
	if err != nil || window.since == nil || !window.since.Equal(now.Add(-30*time.Minute)) || window.until != nil {
		t.Fatalf("--since 30m = %+v, %v", window, err)
	}
	for _, bad := range [][2]string{{"yesterday", ""}, {"", "-5m"}, {"2026-09-27T19:00:00Z", "2026-09-27T18:00:00Z"}} {
		auditExportSince, auditExportUntil = bad[0], bad[1]
		if _, err := parseAuditExportWindow(now); err == nil {
			t.Errorf("--since %q --until %q was accepted", bad[0], bad[1])
		}
	}
}

// The activity rows and the legacy projection follow the same window, and
// the legacy projection the same --newest selection.
func TestAuditExportSourcesFollowTheWindow(t *testing.T) {
	dir := t.TempDir()
	store, err := audit.NewStore(filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	for index, at := range []time.Time{
		time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC),
		time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC),
	} {
		if err := store.InsertActivityEvent(audit.ActivityEventRow{
			ID: "activity-" + string(rune('0'+index)), Timestamp: at, Actor: "admin", Action: "config-update",
			TargetType: "config", TargetID: "guardrail", AfterJSON: `{"mode":"action"}`,
		}); err != nil {
			t.Fatal(err)
		}
	}
	_ = store.Close()
	legacy, err := sql.Open("sqlite", filepath.Join(dir, "legacy-audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Close()
	if _, err := legacy.Exec(`CREATE TABLE audit_events (
		id TEXT, timestamp TEXT, action TEXT, target TEXT, actor TEXT,
		details TEXT, severity TEXT, run_id TEXT)`); err != nil {
		t.Fatal(err)
	}
	for index, stamp := range []string{"2026-09-27T10:00:00Z", "2026-09-27T12:00:00Z", "2026-09-27T11:00:00Z"} {
		if _, err := legacy.Exec(`INSERT INTO audit_events (id,timestamp,action,actor,details,severity,run_id) VALUES (?,?,?,?,?,?,?)`,
			"legacy-"+string(rune('0'+index)), stamp, string(audit.ActionConnectorHook), "defenseclaw", "connector=codex", "INFO", "run-1"); err != nil {
			t.Fatal(err)
		}
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	lines := func(out bytes.Buffer) int {
		if out.Len() == 0 {
			return 0
		}
		return strings.Count(strings.TrimSpace(out.String()), "\n") + 1
	}
	since := time.Date(2026, 9, 27, 11, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		window auditExportWindow
		want   int
	}{{auditExportWindow{since: &since}, 1}, {auditExportWindow{}, 2}} {
		var out bytes.Buffer
		if err := exportActivityLines(db, &out, version.Provenance{}, tc.window); err != nil || lines(out) != tc.want {
			t.Fatalf("activity export in %+v = %q (%v), want %d rows", tc.window, out.String(), err, tc.want)
		}
	}
	legacySince := time.Date(2026, 9, 27, 10, 30, 0, 0, time.UTC)
	var out bytes.Buffer
	if err := exportAuditEventsFallbackWindow(legacy, &out, version.Provenance{}, "", auditExportWindow{since: &legacySince, limit: 1, newest: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"id":"legacy-1"`) || lines(out) != 1 {
		t.Fatalf("fallback window export = %s, want only legacy-1", out.String())
	}
}

// GAP-1170: --include-activity on a 1.0 database (no activity_events rows)
// says why it added nothing instead of looking broken.
func TestIncludeActivityWithoutHistoryNotesWhy(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var out, stderr bytes.Buffer
	if err := appendActivityLines(&stderr, db, &out, version.Provenance{}, auditExportWindow{}); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 || !strings.Contains(stderr.String(), "config-update") {
		t.Fatalf("stdout %q, stderr %q", out.String(), stderr.String())
	}
}

// GAP-2110: a bad --since or --until is a usage error (exit 2) like a bad
// --limit or an unknown flag, and it fails before an -o file is created.
func TestAuditExportBadWindowIsUsageError(t *testing.T) {
	dir := t.TempDir()
	prevCfg, prevOut := cfg, auditExportOut
	prevSince, prevUntil := auditExportSince, auditExportUntil
	t.Cleanup(func() {
		cfg, auditExportOut = prevCfg, prevOut
		auditExportSince, auditExportUntil = prevSince, prevUntil
	})
	cfg = &config.Config{AuditDB: filepath.Join(dir, "audit.db")}
	out := filepath.Join(dir, "out.jsonl")
	auditExportOut = out
	for _, bad := range [][2]string{{"yesterday", ""}, {"", "tomorrow"}, {"2026-09-27T19:00:00Z", "2026-09-27T18:00:00Z"}} {
		auditExportSince, auditExportUntil = bad[0], bad[1]
		err := runAuditExport(auditExportCmd, nil)
		if commandExitCode(err) != 2 || !strings.Contains(fmt.Sprint(err), "--help") {
			t.Errorf("--since %q --until %q = %v (exit %d), want a usage error with exit 2", bad[0], bad[1], err, commandExitCode(err))
		}
		if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
			t.Fatalf("--since %q --until %q created %s", bad[0], bad[1], out)
		}
	}
}
