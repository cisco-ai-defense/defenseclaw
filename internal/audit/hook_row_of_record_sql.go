// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

// A hook decision has one or two local rows. A benign per-user allow keeps
// only its hook_decision row (the connector-hook record is exported only,
// #1384); every other decision, and every decision a 1.0.9 gateway wrote,
// keeps its connector-hook (or connector-hook-synthetic) row beside its
// hook_decision row, both naming the same correlation semantic event. Every
// reader that counts or lists hook decisions takes the connector-hook row
// when there is one and the hook_decision row otherwise, so a decision is
// counted once whichever rows it has. cli/defenseclaw/hook_metrics.py
// (lone_hook_decision_sql, count_once_hook_rows) is the Python form of the
// same rule; both row kinds stay live, and both paths are permanent.

// hookRowSemanticEventSQL is the correlation semantic event id of a row's
// projected record, NULL when the row has none.
func hookRowSemanticEventSQL(projected string) string {
	return `(CASE WHEN json_valid(COALESCE(` + projected + `,'')) THEN json_extract(` + projected +
		`,'$.correlation.semantic_event_id') END)`
}

// LoneHookDecisionSQL is a predicate true for a hook_decision row (alias
// alias, empty for none) that is the only local hook row of its decision.
// tracked reads audit_hook_lone (HookRowsTracked); without it, on a store no
// 1.0.10 gateway has opened, the rule reads the projected records: it
// names a semantic event and no connector-hook or connector-hook-synthetic
// row names the same one. The subquery is not correlated, so SQLite builds
// its set once per statement. A hook_decision row with no semantic event is
// never alone: the gateway keeps the connector-hook row of an uncorrelated
// call.
func LoneHookDecisionSQL(alias string, tracked bool) string {
	prefix := ""
	if alias != "" {
		prefix = alias + "."
	}
	if tracked {
		// audit_hook_lone (hook_row_tracking.go): one key lookup, and no
		// record is read (rel-1-0-10:GAP-0316).
		row := "audit_events.id"
		if alias != "" {
			row = prefix + "id"
		}
		return `(` + prefix + `action = '` + hookDecisionEventName + `' AND EXISTS (SELECT 1 FROM ` + hookLoneTable +
			` AS hook_lone WHERE hook_lone.audit_event_id = ` + row + `))`
	}
	own := hookRowSemanticEventSQL(prefix + "projected_record_json")
	sibling := hookRowSemanticEventSQL("hook_sibling.projected_record_json")
	return `(` + prefix + `action = '` + hookDecisionEventName + `' AND ` + own + ` IS NOT NULL AND ` + own +
		` NOT IN (SELECT ` + sibling + ` FROM audit_events AS hook_sibling WHERE hook_sibling.action IN ('` +
		string(ActionConnectorHook) + `','` + string(ActionConnectorHookSynthetic) + `') AND ` + sibling + ` IS NOT NULL))`
}

// HookDecisionBodySQL is the body of a hook_decision row (alias alias):
// payload_json, else the projected record's body.
func HookDecisionBodySQL(alias string) string {
	prefix := ""
	if alias != "" {
		prefix = alias + "."
	}
	return `COALESCE(NULLIF(` + prefix + `payload_json,''), CASE WHEN json_valid(COALESCE(` + prefix +
		`projected_record_json,'')) THEN json_extract(` + prefix + `projected_record_json,'$.body') END)`
}
