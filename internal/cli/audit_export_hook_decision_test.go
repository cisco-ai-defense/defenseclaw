// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"database/sql"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// A benign per-user allow keeps only its hook_decision row (#1384): the
// audit export adds the v7 connector-hook line of that decision, so it still
// has one connector-hook line per hook decision. A decision whose
// connector-hook row is stored (a block, 1.0.9 data) gets no second one.
func TestRunAuditExportAddsTheConnectorHookLineOfALoneHookDecision(t *testing.T) {
	dir := t.TempDir()
	dbPath := dir + "/audit.db"
	db, err := sql.Open("sqlite", dbPath)
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
		connector TEXT, event_name TEXT, payload_json TEXT, projected_record_json TEXT)`); err != nil {
		t.Fatal(err)
	}
	body := func(action string) string {
		return `{"defenseclaw.hook.event":"PreToolUse","defenseclaw.hook.result":"ok",` +
			`"defenseclaw.guardrail.effective_action":"` + action + `","defenseclaw.guardrail.raw_action":"` + action + `",` +
			`"defenseclaw.guardrail.mode":"enforce","defenseclaw.guardrail.would_block":false,` +
			`"defenseclaw.security.severity":"INFO","defenseclaw.guardrail.latency_ms":12,` +
			`"defenseclaw.hook.body_bytes":196,"defenseclaw.hook.raw_origin":"hook","user.id":"1000"}`
	}
	projected := func(semantic, payload string) string {
		return `{"correlation":{"semantic_event_id":"` + semantic + `"},"body":` + payload + `}`
	}
	insert := func(id, ts, action, eventName, payload, projectedJSON string) {
		if _, err := db.Exec(`INSERT INTO audit_events (id,timestamp,action,actor,details,severity,schema_version,generation,
			connector,session_id,event_name,payload_json,projected_record_json)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			id, ts, action, "defenseclaw", action, "INFO", 7, 0, "claudecode", "s-1", eventName,
			nullIfEmpty(payload), nullIfEmpty(projectedJSON)); err != nil {
			t.Fatal(err)
		}
	}
	// A benign allow of 1.0.10: its hook_decision row only.
	allowBody := body("allow")
	insert("01a1d3df-0000-7000-8000-000000000001", "2026-11-13T07:00:00Z", "hook_decision", "hook_decision",
		allowBody, projected("01a1d3df-0000-7000-8000-00000000aaaa", allowBody))
	// A block: its connector-hook row and its hook_decision row.
	blockBody := body("block")
	insert("01a1d3df-0000-7000-8000-000000000002", "2026-11-13T07:00:01Z", "connector-hook", "legacy.audit.connector.hook",
		"", projected("01a1d3df-0000-7000-8000-00000000bbbb", `{}`))
	insert("01a1d3df-0000-7000-8000-000000000003", "2026-11-13T07:00:02Z", "hook_decision", "hook_decision",
		blockBody, projected("01a1d3df-0000-7000-8000-00000000bbbb", blockBody))
	db.Close()

	prevCfg := cfg
	prevOut, prevConn, prevLimit, prevAct := auditExportOut, auditExportConnector, auditExportLimit, auditExportIncludeActivity
	t.Cleanup(func() {
		cfg = prevCfg
		auditExportOut, auditExportConnector, auditExportLimit, auditExportIncludeActivity = prevOut, prevConn, prevLimit, prevAct
	})
	outPath := dir + "/out.jsonl"
	cfg = &config.Config{AuditDB: dbPath}
	auditExportOut, auditExportConnector, auditExportLimit, auditExportIncludeActivity = outPath, "", 0, false
	if err := runAuditExport(nil, nil); err != nil {
		t.Fatalf("runAuditExport: %v", err)
	}
	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	var connectorHooks []map[string]any
	for _, line := range lines {
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("line not JSON: %v\n%s", err, line)
		}
		if ev["action"] == "connector-hook" {
			connectorHooks = append(connectorHooks, ev)
		}
	}
	if len(lines) != 4 || len(connectorHooks) != 2 {
		t.Fatalf("export lines = %d, connector-hook lines = %d; want 4 and 2:\n%s", len(lines), len(connectorHooks), raw)
	}
	var derived map[string]any
	for _, ev := range connectorHooks {
		if id, _ := ev["id"].(string); strings.HasSuffix(id, hookDecisionConnectorHookIDSuffix) {
			derived = ev
		}
	}
	structured, _ := derived["structured"].(map[string]any)
	if derived["id"] != "01a1d3df-0000-7000-8000-000000000001"+hookDecisionConnectorHookIDSuffix ||
		derived["target"] != "PreToolUse" || structured["action"] != "allow" || structured["mode"] != "action" ||
		structured["schema"] != "defenseclaw.hook.v1" || structured["body_bytes"] != float64(196) ||
		!strings.Contains(derived["details"].(string), "connector=claudecode result=ok action=allow raw_action=allow") {
		t.Fatalf("derived connector-hook line = %v", derived)
	}
}

func nullIfEmpty(value string) any {
	if value == "" {
		return nil
	}
	return value
}
