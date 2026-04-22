// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite" // SQLite driver for export (same as audit.Store)

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/version"
)

var (
	auditExportOut             string
	auditExportIncludeActivity bool
	auditExportLimit           int
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Inspect and export the local audit database",
}

var auditExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export audit_events as JSONL (v7 schema)",
	Long: `Write one JSON object per line. Each audit row is validated against
schemas/audit-event.json before it is written. With --include-activity,
append rows from activity_events validated against activity-event.json.`,
	RunE: runAuditExport,
}

func init() {
	auditExportCmd.Flags().StringVarP(&auditExportOut, "output", "o", "-", "Output file path, or '-' for stdout")
	auditExportCmd.Flags().BoolVar(&auditExportIncludeActivity, "include-activity", false, "Append activity_events payloads (activity-event.json) after audit lines")
	auditExportCmd.Flags().IntVar(&auditExportLimit, "limit", 0, "Max audit rows (0 = unlimited)")

	auditCmd.AddCommand(auditExportCmd)
	rootCmd.AddCommand(auditCmd)
}

// auditActionEnum is the allow-list from schemas/audit-event.json (action field).
var auditActionEnum = map[string]struct{}{
	"init": {}, "stop": {}, "ready": {}, "scan": {}, "scan-start": {}, "rescan": {}, "rescan-start": {},
	"block": {}, "allow": {}, "warn": {}, "quarantine": {}, "restore": {}, "disable": {}, "enable": {},
	"deploy": {}, "drift": {}, "network-egress-blocked": {}, "network-egress-allowed": {},
	"guardrail-block": {}, "guardrail-warn": {}, "guardrail-allow": {},
	"approval-request": {}, "approval-granted": {}, "approval-denied": {},
	"tool-call": {}, "tool-result": {},
	"config-update": {}, "policy-update": {}, "policy-reload": {}, "action": {},
	"acknowledge-alerts": {}, "dismiss-alerts": {},
	"webhook-delivered": {}, "webhook-failed": {}, "sink-failure": {}, "sink-restored": {},
	"alert": {},
}

func runAuditExport(_ *cobra.Command, _ []string) error {
	if cfg == nil {
		return fmt.Errorf("audit export: config not loaded")
	}
	version.SetBinaryVersion(appVersion)
	prov := version.Current()

	db, err := sql.Open("sqlite", cfg.AuditDB)
	if err != nil {
		return fmt.Errorf("audit export: open db: %w", err)
	}
	defer db.Close()

	out := io.Writer(os.Stdout)
	if auditExportOut != "" && auditExportOut != "-" {
		f, err := os.Create(auditExportOut)
		if err != nil {
			return fmt.Errorf("audit export: create output: %w", err)
		}
		defer f.Close()
		if err := os.Chmod(auditExportOut, 0o600); err != nil {
			return fmt.Errorf("audit export: chmod: %w", err)
		}
		out = f
	}

	q := `SELECT id, timestamp, action, target, actor, details, severity, run_id,
session_id, trace_id, agent_id, agent_name, agent_instance_id, sidecar_instance_id,
schema_version, content_hash, generation, binary_version,
destination_app, tool_name, tool_id, policy_id
FROM audit_events ORDER BY timestamp ASC`
	args := []any{}
	if auditExportLimit > 0 {
		q += ` LIMIT ?`
		args = append(args, auditExportLimit)
	}

	rows, err := db.Query(q, args...)
	if err != nil {
		// Older DBs may miss v7 columns — fall back to minimal projection.
		if err := exportAuditEventsFallback(db, out, prov); err != nil {
			return err
		}
		if auditExportIncludeActivity {
			return exportActivityLines(db, out, prov)
		}
		return nil
	}
	defer rows.Close()

	for rows.Next() {
		var (
			id, ts, action, actor                      string
			target, details, severity, runID           sql.NullString
			sessionID, traceID                         sql.NullString
			agentID, agentName, agentInst, sidecarInst sql.NullString
			schemaVer                                  sql.NullInt64
			contentHash, binVer                        sql.NullString
			gen                                        sql.NullInt64
			destApp, toolName, toolID, policyID        sql.NullString
		)
		if err := rows.Scan(
			&id, &ts, &action, &target, &actor, &details, &severity, &runID,
			&sessionID, &traceID,
			&agentID, &agentName, &agentInst, &sidecarInst,
			&schemaVer, &contentHash, &gen, &binVer,
			&destApp, &toolName, &toolID, &policyID,
		); err != nil {
			return fmt.Errorf("audit export: scan: %w", err)
		}

		line, err := buildAuditEventLine(id, ts, action,
			ns(target), ns(details), ns(severity), ns(runID),
			ns(sessionID), ns(traceID),
			actor,
			ns(agentID), ns(agentName), ns(agentInst), ns(sidecarInst),
			schemaVer, ns(contentHash), gen, ns(binVer),
			ns(destApp), ns(toolName), ns(toolID), ns(policyID),
			prov,
		)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintln(out, string(line)); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	if auditExportIncludeActivity {
		if err := exportActivityLines(db, out, prov); err != nil {
			return err
		}
	}
	return nil
}

func exportAuditEventsFallback(db *sql.DB, out io.Writer, prov version.Provenance) error {
	rows, err := db.Query(`SELECT id, timestamp, action, target, actor, details, severity, run_id FROM audit_events ORDER BY timestamp ASC`)
	if err != nil {
		return fmt.Errorf("audit export: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, ts, action, actor string
		var target, details, severity, runID sql.NullString
		if err := rows.Scan(&id, &ts, &action, &target, &actor, &details, &severity, &runID); err != nil {
			return fmt.Errorf("audit export: scan: %w", err)
		}
		line, err := buildAuditEventLine(id, ts, action,
			ns(target), ns(details), ns(severity), ns(runID),
			"", "",
			actor,
			"", "", "", "",
			sql.NullInt64{}, "", sql.NullInt64{}, "",
			"", "", "", "",
			prov,
		)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintln(out, string(line)); err != nil {
			return err
		}
	}
	return rows.Err()
}

func ns(s sql.NullString) string {
	if !s.Valid {
		return ""
	}
	return s.String
}

func buildAuditEventLine(
	id, ts, action, target, details, severity, runID string,
	sessionID, traceID string,
	actor string,
	agentID, agentName, agentInst, sidecarInst string,
	schemaVer sql.NullInt64, contentHash string, gen sql.NullInt64, binVer string,
	destApp, toolName, toolID, policyID string,
	prov version.Provenance,
) ([]byte, error) {
	actionOut, detailsOut := normalizeAuditAction(action, details)
	sev := normalizeSeverity(severity)
	act := strings.TrimSpace(actor)
	if act == "" {
		act = "system:defenseclaw"
	}
	sv := int(version.SchemaVersion)
	if schemaVer.Valid && schemaVer.Int64 >= 7 {
		sv = int(schemaVer.Int64)
	}
	ch := strings.TrimSpace(contentHash)
	if ch == "" {
		ch = prov.ContentHash
	}
	g := prov.Generation
	if gen.Valid && gen.Int64 >= 0 {
		g = uint64(gen.Int64)
	}
	bver := binVer
	if strings.TrimSpace(bver) == "" {
		bver = prov.BinaryVersion
	}

	ev := map[string]any{
		"id":                  id,
		"timestamp":           normalizeTimestamp(ts),
		"action":              actionOut,
		"actor":               act,
		"schema_version":      sv,
		"severity":            sev,
		"content_hash":        nilIfEmptyStr(ch),
		"generation":          g,
		"binary_version":      nilIfEmptyStr(bver),
		"run_id":              strPtr(runID),
		"session_id":          strPtr(sessionID),
		"trace_id":            strPtr(traceID),
		"span_id":             nil,
		"target":              strPtr(target),
		"details":             strPtr(detailsOut),
		"agent_id":            strPtr(agentID),
		"agent_name":          strPtr(agentName),
		"agent_instance_id":   strPtr(agentInst),
		"sidecar_instance_id": strPtr(sidecarInst),
		"destination_app":     strPtr(destApp),
		"tool_name":           strPtr(toolName),
		"tool_id":             strPtr(toolID),
		"policy_id":           strPtr(policyID),
	}
	if err := validateAuditEventMap(ev); err != nil {
		return nil, fmt.Errorf("audit export: %w", err)
	}
	return json.Marshal(ev)
}

func nilIfEmptyStr(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}

func strPtr(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}

func normalizeTimestamp(ts string) string {
	// SQLite may store ISO strings without timezone — ensure RFC3339-like.
	ts = strings.TrimSpace(ts)
	if ts == "" {
		return time.Now().UTC().Format(time.RFC3339Nano)
	}
	if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		return t.UTC().Format(time.RFC3339Nano)
	}
	if t, err := time.Parse("2006-01-02 15:04:05", ts); err == nil {
		return t.UTC().Format(time.RFC3339Nano)
	}
	return ts
}

func normalizeSeverity(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "INFO"
	}
	if s == "ERROR" {
		return "WARN"
	}
	if s == "ACK" {
		return "INFO"
	}
	// schema: CRITICAL, HIGH, MEDIUM, LOW, INFO, WARN
	switch s {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "WARN":
		return s
	default:
		return "INFO"
	}
}

func normalizeAuditAction(action, details string) (string, string) {
	a := strings.TrimSpace(action)
	if _, ok := auditActionEnum[a]; ok {
		return a, details
	}
	prefix := "legacy_action=" + a
	if strings.TrimSpace(details) == "" {
		return "action", prefix
	}
	return "action", prefix + " | " + details
}

var auditSeverityEnum = map[string]struct{}{
	"CRITICAL": {}, "HIGH": {}, "MEDIUM": {}, "LOW": {}, "INFO": {}, "WARN": {},
}

func validateAuditEventMap(ev map[string]any) error {
	if _, ok := ev["id"]; !ok {
		return fmt.Errorf("invalid audit event: missing id")
	}
	if _, ok := ev["timestamp"]; !ok {
		return fmt.Errorf("invalid audit event: missing timestamp")
	}
	act, _ := ev["action"].(string)
	if _, ok := auditActionEnum[act]; !ok {
		return fmt.Errorf("invalid audit event: unknown action %q", act)
	}
	sev, _ := ev["severity"].(string)
	if _, ok := auditSeverityEnum[sev]; !ok {
		return fmt.Errorf("invalid audit event: severity %q", sev)
	}
	sv, ok := ev["schema_version"].(int)
	if !ok || sv < 7 {
		return fmt.Errorf("invalid audit event: schema_version")
	}
	return nil
}

func exportActivityLines(db *sql.DB, out io.Writer, prov version.Provenance) error {
	exists, err := tableExists(db, "activity_events")
	if err != nil || !exists {
		return nil
	}
	rows, err := db.Query(`
SELECT actor, action, target_type, target_id, reason,
       before_json, after_json, diff_json, version_from, version_to
FROM activity_events ORDER BY timestamp ASC`)
	if err != nil {
		return fmt.Errorf("audit export: activity query: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var actor, action, tt, tid string
		var reason sql.NullString
		var beforeJ, afterJ, diffJ sql.NullString
		var vf, vt sql.NullString
		if err := rows.Scan(&actor, &action, &tt, &tid, &reason, &beforeJ, &afterJ, &diffJ, &vf, &vt); err != nil {
			return fmt.Errorf("audit export: activity scan: %w", err)
		}
		payload, err := buildActivityPayload(actor, action, tt, tid, reason, beforeJ, afterJ, diffJ, vf, vt, prov)
		if err != nil {
			return err
		}
		b, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		if err := validateActivityPayloadMap(payload); err != nil {
			return fmt.Errorf("audit export: activity: %w", err)
		}
		if _, err := fmt.Fprintln(out, string(b)); err != nil {
			return err
		}
	}
	return rows.Err()
}

func tableExists(db *sql.DB, name string) (bool, error) {
	var n int
	err := db.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, name,
	).Scan(&n)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func buildActivityPayload(
	actor, action, targetType, targetID string,
	reason sql.NullString,
	beforeJ, afterJ, diffJ sql.NullString,
	vf, vt sql.NullString,
	prov version.Provenance,
) (map[string]any, error) {
	_ = prov // reserved for future envelope fields
	act := normalizeActivityAction(action)
	m := map[string]any{
		"actor":        actor,
		"action":       act,
		"target_type":  targetType,
		"target_id":    targetID,
		"reason":       strPtr(ns(reason)),
		"version_from": strPtr(ns(vf)),
		"version_to":   strPtr(ns(vt)),
	}
	m["before"] = jsonRawToAny(ns(beforeJ))
	m["after"] = jsonRawToAny(ns(afterJ))
	if diffJ.Valid && strings.TrimSpace(diffJ.String) != "" {
		var diff any
		if err := json.Unmarshal([]byte(diffJ.String), &diff); err == nil {
			m["diff"] = diff
		}
	}
	return m, nil
}

func normalizeActivityAction(a string) string {
	a = strings.TrimSpace(a)
	if _, ok := activityActionEnum[a]; ok {
		return a
	}
	return "action"
}

func jsonRawToAny(s string) any {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return nil
	}
	return v
}

// activityActionEnum is the action subset from schemas/activity-event.json.
var activityActionEnum = map[string]struct{}{
	"config-update": {}, "policy-update": {}, "policy-reload": {},
	"block": {}, "allow": {}, "quarantine": {}, "restore": {}, "disable": {}, "enable": {},
	"action": {}, "acknowledge-alerts": {}, "dismiss-alerts": {}, "deploy": {}, "stop": {},
}

func validateActivityPayloadMap(m map[string]any) error {
	for _, k := range []string{"actor", "action", "target_type", "target_id"} {
		if v, ok := m[k].(string); !ok || strings.TrimSpace(v) == "" {
			return fmt.Errorf("invalid activity payload: %q", k)
		}
	}
	act := m["action"].(string)
	if _, ok := activityActionEnum[act]; !ok {
		return fmt.Errorf("invalid activity action %q", act)
	}
	return nil
}
