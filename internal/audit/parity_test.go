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

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/version"
)

// TestAuditEventMultiConnectorRoundTrip proves the migration-16
// columns survive a full LogEvent -> SQLite -> ListEvents round trip.
// This is the SQLite leg of the DN2 parity contract: the connector
// identity fields a hook decision stamps must come back out of the DB
// byte-for-byte, not get silently dropped by an INSERT or scan that
// forgot a column.
func TestAuditEventMultiConnectorRoundTrip(t *testing.T) {
	l := newTestLogger(t)
	in := Event{
		Action:      string(ActionConnectorHook),
		Target:      "pre_tool_call",
		Actor:       "defenseclaw",
		Severity:    "INFO",
		Connector:   "antigravity",
		StepIdx:     3,
		Enforced:    true,
		RulePackDir: "/etc/defenseclaw/rules/antigravity",
	}
	if err := l.store.LogEvent(in); err != nil {
		t.Fatalf("LogEvent: %v", err)
	}
	events, err := l.store.ListEvents(1)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	got := events[0]
	if got.Connector != in.Connector {
		t.Errorf("connector = %q, want %q", got.Connector, in.Connector)
	}
	if got.StepIdx != in.StepIdx {
		t.Errorf("step_idx = %d, want %d", got.StepIdx, in.StepIdx)
	}
	if got.Enforced != in.Enforced {
		t.Errorf("enforced = %v, want %v", got.Enforced, in.Enforced)
	}
	if got.RulePackDir != in.RulePackDir {
		t.Errorf("rule_pack_dir = %q, want %q", got.RulePackDir, in.RulePackDir)
	}
}

// TestAuditEventMultiConnectorZeroValues pins the "absent" encoding:
// an event that carries none of the new fields must read back with the
// zero values (enforced=false from a NULL column, step_idx=0), not with
// spurious defaults. This guards the nullBool/nullInt encoding so a
// non-hook admin row never looks like an enforced turn.
func TestAuditEventMultiConnectorZeroValues(t *testing.T) {
	l := newTestLogger(t)
	if err := l.store.LogEvent(Event{
		Action: string(ActionPolicyReload),
		Actor:  "cli:bob",
	}); err != nil {
		t.Fatalf("LogEvent: %v", err)
	}
	events, err := l.store.ListEvents(1)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	got := events[0]
	if got.Connector != "" || got.StepIdx != 0 || got.Enforced || got.RulePackDir != "" {
		t.Errorf("non-hook row leaked multi-connector values: %+v", got)
	}
}

// TestAuditMigrationIdempotentForwardCompat opens a store, persists a
// multi-connector row, then re-runs Init (which re-applies the migration
// list). Migration 16's ADD COLUMNs are hasColumnDB-guarded, so a second
// Init must be a no-op and the existing row + a new row must both read
// back intact. This is the migration forward-compat tripwire.
func TestAuditMigrationIdempotentForwardCompat(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "audit.db")

	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.Init(); err != nil {
		t.Fatalf("Init #1: %v", err)
	}
	if err := store.LogEvent(Event{
		Action:    string(ActionConnectorHook),
		Actor:     "defenseclaw",
		Connector: "codex",
		StepIdx:   1,
	}); err != nil {
		t.Fatalf("LogEvent #1: %v", err)
	}
	// Re-running Init must not error (idempotent ADD COLUMN) and must
	// not disturb existing data.
	if err := store.Init(); err != nil {
		t.Fatalf("Init #2 (idempotency): %v", err)
	}
	if err := store.LogEvent(Event{
		Action:    string(ActionConnectorHook),
		Actor:     "defenseclaw",
		Connector: "claudecode",
		StepIdx:   2,
	}); err != nil {
		t.Fatalf("LogEvent #2: %v", err)
	}
	events, err := store.ListEvents(10)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	_ = store.Close()

	seen := map[string]int{}
	for _, e := range events {
		if e.Connector != "" {
			seen[e.Connector] = e.StepIdx
		}
	}
	if seen["codex"] != 1 || seen["claudecode"] != 2 {
		t.Errorf("rows did not survive re-Init: %v", seen)
	}
}

// TestAuditSchemaVersionUnchanged documents that adding the
// multi-connector columns (migration 16) is an ADDITIVE change and must
// NOT bump the v7 provenance envelope version. The provenance package
// has its own pin; this restates it from the audit side so a future
// edit that conflates "new optional columns" with "breaking envelope
// bump" trips here too.
func TestAuditSchemaVersionUnchanged(t *testing.T) {
	if version.SchemaVersion != 7 {
		t.Fatalf("version.SchemaVersion = %d, want 7 (migration 16 is additive, not an envelope bump)", version.SchemaVersion)
	}
}

// TestMultiConnectorSinkParity is the DN2 schema-contract tripwire. It
// asserts that the connector identity field set is declared in each of
// the three sink schemas a hook decision fans out to:
//
//   - SQLite                : schemas/audit-event.json
//   - structured logs (JSON): schemas/hook-audit-envelope.json
//   - OTel log record       : schemas/otel/connector-telemetry-event.schema.json
//
// plus the W3C trace-context quad in the SQLite schema (produced by the
// OTel SDK via the traceparent header — no populator code, but the
// schema must declare it so a future regression dropping a field fails
// CI rather than silently losing conversational/trace structure).
func TestMultiConnectorSinkParity(t *testing.T) {
	repoRoot := filepath.Join("..", "..")

	connectorFields := []string{"connector", "step_idx", "enforced", "rule_pack_dir"}

	// SQLite sink.
	auditProps := schemaProperties(t, filepath.Join(repoRoot, "schemas", "audit-event.json"))
	for _, f := range connectorFields {
		if _, ok := auditProps[f]; !ok {
			t.Errorf("audit-event.json missing property %q", f)
		}
	}
	for _, f := range []string{"trace_id", "span_id", "parent_span_id", "trace_flags"} {
		if _, ok := auditProps[f]; !ok {
			t.Errorf("audit-event.json missing W3C trace-context property %q", f)
		}
	}

	// Structured-logs sink (hook audit envelope).
	hookProps := schemaProperties(t, filepath.Join(repoRoot, "schemas", "hook-audit-envelope.json"))
	for _, f := range connectorFields {
		if _, ok := hookProps[f]; !ok {
			t.Errorf("hook-audit-envelope.json missing property %q", f)
		}
	}

	// OTel sink (connector telemetry log record). The connector
	// dimensions live under $defs.attributeDefinitions.properties with
	// the defenseclaw.connector.* namespace.
	otelDefs := otelAttributeDefinitions(t, filepath.Join(repoRoot, "schemas", "otel", "connector-telemetry-event.schema.json"))
	otelFields := []string{
		"defenseclaw.connector.source",
		"defenseclaw.connector.step_idx",
		"defenseclaw.connector.enforced",
		"defenseclaw.connector.rule_pack_dir",
	}
	for _, f := range otelFields {
		if _, ok := otelDefs[f]; !ok {
			t.Errorf("connector-telemetry-event.schema.json missing attribute definition %q", f)
		}
	}
}

// schemaProperties loads a JSON schema and returns its top-level
// "properties" object.
func schemaProperties(t *testing.T, path string) map[string]any {
	t.Helper()
	doc := loadSchema(t, path)
	props, ok := doc["properties"].(map[string]any)
	if !ok {
		t.Fatalf("%s: no top-level properties object", path)
	}
	return props
}

// otelAttributeDefinitions returns
// $defs.attributeDefinitions.properties for the OTel connector
// telemetry schema.
func otelAttributeDefinitions(t *testing.T, path string) map[string]any {
	t.Helper()
	doc := loadSchema(t, path)
	defs, ok := doc["$defs"].(map[string]any)
	if !ok {
		t.Fatalf("%s: no $defs object", path)
	}
	attrDefs, ok := defs["attributeDefinitions"].(map[string]any)
	if !ok {
		t.Fatalf("%s: no $defs.attributeDefinitions object", path)
	}
	props, ok := attrDefs["properties"].(map[string]any)
	if !ok {
		t.Fatalf("%s: no $defs.attributeDefinitions.properties object", path)
	}
	return props
}

func loadSchema(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return doc
}
