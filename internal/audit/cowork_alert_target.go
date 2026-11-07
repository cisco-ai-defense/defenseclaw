// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package audit

import "strings"

// coworkAlertTarget maps the Target alerts print for a Claude Cowork call
// back to the stored one (GAP-0047, cowork audit M1). Cowork is a surface of
// the claudecode connector, so its rows store claudecode:PreToolUse (a
// finding) or PreToolUse (a hook row), and alerts print cowork:PreToolUse and
// "cowork PreToolUse" for them (cowork_hook_target in
// cli/defenseclaw/alert_semantics.py). ok=false for any other target.
func coworkAlertTarget(target string) (stored string, ok bool) {
	text := strings.TrimSpace(target)
	if head, event, prefixed := strings.Cut(text, ":"); prefixed && strings.EqualFold(strings.TrimSpace(head), "cowork") {
		if event = strings.TrimSpace(event); event != "" {
			return "claudecode:" + event, true
		}
		return "", false
	}
	if head, rest, spaced := strings.Cut(text, " "); spaced && strings.EqualFold(head, "cowork") {
		if rest = strings.TrimSpace(rest); rest != "" {
			return rest, true
		}
	}
	return "", false
}

// coworkMarkerSQL is true for an audit row (alias a) of a Cowork call: the
// hook audit envelope's surface or extra.surface (the check of
// coworkaudit.lastEventsQuery), the hook decision's
// defenseclaw.agent.surface, or, for a legacy row with no valid structured
// payload, a surface=cowork token of the details before details_json. The
// details of a row with a payload hold free text (an unquoted reason=, a
// raw_payload=), so a terminal call that only mentions surface=cowork is not
// Cowork (cowork audit review 2 N1). The payload is the one alerts read: the
// row's structured_json, or a native v8 row's payload_json
// (StructuredJSONReadSQL). It mirrors _event_surface in
// cli/defenseclaw/commands/cmd_alerts.py, so the selector matches the rows
// alerts label Cowork and no others.
func coworkMarkerSQL(a string) string {
	s := "COALESCE(" + StructuredJSONReadSQL(a, true, true) + ",'')"
	d := "LOWER(COALESCE(" + a + ".details,''))"
	return `((instr(` + s + `,'cowork') > 0 AND json_valid(` + s + `) AND 'cowork' IN (
			LOWER(COALESCE(json_extract(` + s + `,'$.surface'),'')),
			LOWER(COALESCE(json_extract(` + s + `,'$.extra.surface'),'')),
			LOWER(COALESCE(json_extract(` + s + `,'$."defenseclaw.agent.surface"'),''))))
		OR ((` + s + ` = '' OR NOT json_valid(` + s + `)) AND instr(' ' || CASE WHEN instr(` + d + `,' details_json=') > 0
				THEN substr(` + d + `,1,instr(` + d + `,' details_json=') - 1) ELSE ` + d + ` END || ' ',
			' surface=cowork ') > 0))`
}

// coworkAlertTargetPredicateSQL selects the stored claudecode target of a
// Cowork call when the alert row, or for a finding the hook rows of its
// request (the rows hook_details_for_alerts reads in cli/defenseclaw/db.py),
// carry the Cowork marker. A Claude Code terminal call with the same stored
// target never matches.
func coworkAlertTargetPredicateSQL(target, stored string) (string, []any) {
	return `(event.target = ? OR (event.target = ?
		AND LOWER(COALESCE(event.connector,'')) = 'claudecode'
		AND (` + coworkMarkerSQL("event") + `
			OR (event.action = 'scan-finding' AND COALESCE(event.request_id,'') <> '' AND EXISTS (
				SELECT 1 FROM audit_events AS surface_row
				WHERE surface_row.request_id = event.request_id
				  AND (surface_row.action IN ('connector-hook','guardrail-verdict','hook_decision','action')
				       OR surface_row.action LIKE 'inspect-tool-%')
				  AND ` + coworkMarkerSQL("surface_row") + `)))))`, []any{target, stored}
}
