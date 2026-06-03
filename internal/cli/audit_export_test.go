// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"database/sql"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// TestNormalizeAuditAction_PassesThroughKnownActions guards the F3 fix:
// `defenseclaw audit export` previously kept a hand-maintained copy of the
// audit action enum that silently fell behind whenever internal/audit added
// new actions (connector-hook, connector-hook-synthetic, codex.notify.*,
// otel.ingest.*, asset-policy, …). The result was that perfectly valid
// rows had their `action` field rewritten to `"action"` with the original
// stuffed into `legacy_action=…`, breaking every Splunk dashboard that
// keyed on the actual action. This test enumerates the canonical registry
// so a future addition that forgets to wire through audit.AllActions()
// fails loudly.
func TestNormalizeAuditAction_PassesThroughKnownActions(t *testing.T) {
	t.Parallel()
	for _, a := range audit.AllActions() {
		s := string(a)
		got, gotDetails := normalizeAuditAction(s, "x=1")
		if got != s {
			t.Errorf("normalizeAuditAction(%q) action=%q, want %q (regression: action enum drifted from internal/audit)", s, got, s)
		}
		if gotDetails != "x=1" {
			t.Errorf("normalizeAuditAction(%q) details=%q, want %q (legacy_action prefix incorrectly applied)", s, gotDetails, "x=1")
		}
	}
}

// TestNormalizeAuditAction_AcceptsCodexNotifyDynamicSuffix exercises the
// dynamic-suffix family `codex.notify.<sanitized-type>`. The audit schema
// permits these via a regex (^codex\.notify\.[a-z0-9._-]{1,64}$) and the
// export tool MUST honour the same rule so a notify with an unusual but
// well-formed suffix (e.g. codex.notify.task-completed) is not silently
// downgraded to the generic "action" bucket.
func TestNormalizeAuditAction_AcceptsCodexNotifyDynamicSuffix(t *testing.T) {
	t.Parallel()
	cases := []string{
		"codex.notify.agent-turn-complete",
		"codex.notify.task-completed",
		"codex.notify.tool_invoked",
		"codex.notify.foo.bar.baz",
	}
	for _, s := range cases {
		got, _ := normalizeAuditAction(s, "")
		if got != s {
			t.Errorf("normalizeAuditAction(%q) = %q, want %q (codex.notify dynamic-suffix not preserved)", s, got, s)
		}
	}
}

// TestNormalizeAuditAction_RewritesUnknownActions confirms the fallback
// path still works: a genuinely unknown action (typo, attacker injection,
// old code path) is rewritten to "action" with `legacy_action=<orig>`
// prepended to the details blob. This is the original intent of the
// helper; the F3 fix narrowed the trigger set but did not remove the
// safety rewrite.
func TestNormalizeAuditAction_RewritesUnknownActions(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in            string
		details       string
		wantAction    string
		wantHasPrefix string
	}{
		{"definitely-not-a-real-action", "x=1", "action", "legacy_action=definitely-not-a-real-action"},
		{"capital-letters-NOT-allowed", "", "action", "legacy_action=capital-letters-NOT-allowed"},
		// codex.notify suffix with disallowed chars is NOT honoured.
		{"codex.notify.HAS-CAPS", "", "action", "legacy_action=codex.notify.HAS-CAPS"},
	}
	for _, tc := range cases {
		gotAction, gotDetails := normalizeAuditAction(tc.in, tc.details)
		if gotAction != tc.wantAction {
			t.Errorf("normalizeAuditAction(%q) action=%q, want %q", tc.in, gotAction, tc.wantAction)
		}
		if !strings.HasPrefix(gotDetails, tc.wantHasPrefix) {
			t.Errorf("normalizeAuditAction(%q) details=%q, want prefix %q", tc.in, gotDetails, tc.wantHasPrefix)
		}
	}
}

// TestIsKnownAuditAction_DelegatesToAuditPackage asserts that the helper
// stays a thin wrapper around audit.IsKnownAction + audit.IsKnownActionPrefix.
// If a future change re-introduces a local map this test will fail because
// it will diverge from the canonical registry the moment any new action is
// added on the audit side.
func TestIsKnownAuditAction_DelegatesToAuditPackage(t *testing.T) {
	t.Parallel()
	for _, a := range audit.AllActions() {
		if !isKnownAuditAction(string(a)) {
			t.Errorf("isKnownAuditAction(%q) = false, want true (drift from internal/audit/actions.go)", a)
		}
	}
	if isKnownAuditAction("not-a-real-action") {
		t.Errorf("isKnownAuditAction accepted unknown action; want false")
	}
}

// TestAuditEventConnector covers the attribution precedence: structured
// payload first (authoritative), then a connector= token in details, then "".
func TestAuditEventConnector(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		details    string
		structured string
		want       string
	}{
		{"structured wins", `connector=codex`, `{"connector":"ClaudeCode"}`, "claudecode"},
		{"details fallback", `result=ok connector=Codex would_block=false`, ``, "codex"},
		{"structured only", ``, `{"connector":"antigravity"}`, "antigravity"},
		{"none", `result=ok would_block=false`, `{"event":"PreToolUse"}`, ""},
		{"malformed structured falls back to details", `connector=codex`, `{not json`, "codex"},
	}
	for _, tc := range cases {
		if got := auditEventConnector(tc.details, tc.structured); got != tc.want {
			t.Errorf("%s: auditEventConnector(%q,%q)=%q want %q", tc.name, tc.details, tc.structured, got, tc.want)
		}
	}
}

// TestRunAuditExport_ConnectorFilter writes a tiny audit DB with rows from
// two connectors plus one unattributed row, then asserts --connector exports
// only the matching connector's rows.
func TestRunAuditExport_ConnectorFilter(t *testing.T) {
	dir := t.TempDir()
	dbPath := dir + "/audit.db"
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE audit_events (
		id TEXT, timestamp TEXT, action TEXT, target TEXT, actor TEXT,
		details TEXT, structured_json TEXT, severity TEXT, run_id TEXT,
		session_id TEXT, trace_id TEXT, agent_id TEXT, agent_name TEXT,
		agent_instance_id TEXT, sidecar_instance_id TEXT, schema_version INTEGER,
		content_hash TEXT, generation INTEGER, binary_version TEXT,
		destination_app TEXT, tool_name TEXT, tool_id TEXT, policy_id TEXT)`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	insert := func(id, ts, details, structured string) {
		if _, err := db.Exec(
			`INSERT INTO audit_events (id,timestamp,action,actor,details,structured_json,severity,schema_version,generation)
			 VALUES (?,?,?,?,?,?,?,?,?)`,
			id, ts, string(audit.ActionConnectorHook), "defenseclaw", details, structured, "INFO", 7, 0,
		); err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
	}
	insert("11111111-1111-1111-1111-111111111111", "2026-05-19T12:00:00Z", `connector=codex`, `{"connector":"codex"}`)
	insert("22222222-2222-2222-2222-222222222222", "2026-05-19T12:00:01Z", `connector=claudecode`, `{"connector":"claudecode"}`)
	insert("33333333-3333-3333-3333-333333333333", "2026-05-19T12:00:02Z", `connector=codex`, `{"connector":"codex"}`)
	db.Close()

	// Drive runAuditExport via its package-level state.
	prevCfg := cfg
	prevOut, prevConn, prevLimit, prevAct := auditExportOut, auditExportConnector, auditExportLimit, auditExportIncludeActivity
	t.Cleanup(func() {
		cfg = prevCfg
		auditExportOut, auditExportConnector, auditExportLimit, auditExportIncludeActivity = prevOut, prevConn, prevLimit, prevAct
	})

	outPath := dir + "/out.jsonl"
	cfg = &config.Config{AuditDB: dbPath}
	auditExportOut = outPath
	auditExportConnector = "codex"
	auditExportLimit = 0
	auditExportIncludeActivity = false

	if err := runAuditExport(nil, nil); err != nil {
		t.Fatalf("runAuditExport: %v", err)
	}
	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read out: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2 (codex rows only):\n%s", len(lines), raw)
	}
	for _, ln := range lines {
		var ev map[string]any
		if err := json.Unmarshal([]byte(ln), &ev); err != nil {
			t.Fatalf("line not JSON: %v\n%s", err, ln)
		}
		s, _ := ev["structured"].(map[string]any)
		if s == nil || s["connector"] != "codex" {
			t.Fatalf("non-codex row leaked through filter: %s", ln)
		}
	}
}

func TestBuildAuditEventLineIncludesStructuredPayload(t *testing.T) {
	line, err := buildAuditEventLine(
		"00000000-0000-0000-0000-000000000001",
		"2026-05-19T12:00:00Z",
		string(audit.ActionConnectorHook),
		"PreToolUse",
		`connector=codex result=ok details_json="{\"schema\":\"defenseclaw.hook.v1\"}"`,
		"INFO",
		"run-1",
		`{"schema":"defenseclaw.hook.v1","connector":"codex","event":"PreToolUse","result":"ok","would_block":false}`,
		"session-1",
		"trace-1",
		"defenseclaw",
		"agent-1",
		"codex",
		"instance-1",
		"sidecar-1",
		sql.NullInt64{Int64: 7, Valid: true},
		"hash-1",
		sql.NullInt64{Int64: 2, Valid: true},
		"0.0.0-test",
		"codex",
		"shell",
		"tool-1",
		"policy-1",
		version.Provenance{SchemaVersion: 7, ContentHash: "hash-1", Generation: 2, BinaryVersion: "0.0.0-test"},
	)
	if err != nil {
		t.Fatalf("buildAuditEventLine: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(line, &got); err != nil {
		t.Fatalf("export line is not JSON: %v\n%s", err, string(line))
	}
	structured, ok := got["structured"].(map[string]any)
	if !ok {
		t.Fatalf("structured missing or wrong type: %#v", got["structured"])
	}
	if structured["schema"] != "defenseclaw.hook.v1" || structured["connector"] != "codex" {
		t.Fatalf("structured payload mismatch: %#v", structured)
	}
}
