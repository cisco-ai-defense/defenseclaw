// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import "strings"

// legacyCompatibilityEventPrefix names the compatibility-only v8 records the
// legacy audit logger writes. Their payload_json is the compatibility body
// (actor, details, target, structured_json as text), not the structured fields.
const legacyCompatibilityEventPrefix = "legacy.audit."

// IsLegacyCompatibilityEventName reports whether a v8 event name is a
// legacy.audit.* compatibility record.
func IsLegacyCompatibilityEventName(name string) bool {
	return strings.HasPrefix(name, legacyCompatibilityEventPrefix)
}

// StructuredJSONReadSQL is the SQL that reads a row's structured fields.
// A native v8 row stores them once, in payload_json, and leaves
// structured_json NULL (GAP-0614); a legacy or compatibility row keeps its
// own structured_json. alias qualifies the columns ("" for none). A database
// without the v8 columns has only structured_json.
func StructuredJSONReadSQL(alias string, hasPayloadJSON, hasEventName bool) string {
	prefix := ""
	if alias != "" {
		prefix = alias + "."
	}
	if !hasPayloadJSON || !hasEventName {
		return prefix + "structured_json"
	}
	return "COALESCE(NULLIF(" + prefix + "structured_json, ''), CASE WHEN " + prefix +
		"event_name IS NOT NULL AND " + prefix + "event_name NOT LIKE '" +
		legacyCompatibilityEventPrefix + "%' THEN " + prefix + "payload_json END)"
}

// structuredJSONReadSQL is StructuredJSONReadSQL for this store's schema.
func (s *Store) structuredJSONReadSQL(alias string) string {
	hasPayload, err := hasColumnDB(s.db, "audit_events", "payload_json")
	if err != nil {
		hasPayload = false
	}
	hasEventName, err := hasColumnDB(s.db, "audit_events", "event_name")
	if err != nil {
		hasEventName = false
	}
	return StructuredJSONReadSQL(alias, hasPayload, hasEventName)
}
