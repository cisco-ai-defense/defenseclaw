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

package config

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config/internal/cfgtxn"
)

// migratedByOldRelease is a managed config as a 1.0.0-1.0.2 migration left
// it (a Cursor fail mode rewritten to open) and the record it wrote.
func migratedByOldRelease(t *testing.T, body, path string) ([]byte, MigrationRecord) {
	t.Helper()
	raw := []byte(body)
	return raw, MigrationRecord{
		SchemaVersion: MigrationRecordSchemaVersion, FromVersion: 8, ToVersion: 9, Actor: "lifecycle",
		MigratedAt:   "2026-09-01T00:00:00Z",
		SourceSHA256: strings.Repeat("a", 64), ResultSHA256: cfgtxn.SHA256Hex(raw),
		Moved: []MigrationMove{{Source: "config", From: path, To: path, Value: "open"}},
	}
}

const managedCursorConnectorOpen = `config_version: 9
deployment_mode: managed_enterprise
enterprise:
  profile: standalone
guardrail:
  mode: observe
  connectors:
    cursor:
      hook_fail_mode: open
`

const managedCursorGlobalOpen = `config_version: 9
deployment_mode: managed_enterprise
enterprise:
  profile: standalone
guardrail:
  mode: observe
  connector: cursor
  hook_fail_mode: open
`

func TestRepairMigratedCursorFailModeRestoresClosedOnce(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	t.Setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "")
	for path, body := range map[string]string{
		migratedCursorConnectorFailMode: managedCursorConnectorOpen,
		migratedGlobalFailMode:          managedCursorGlobalOpen,
	} {
		t.Run(path, func(t *testing.T) {
			raw, record := migratedByOldRelease(t, body, path)
			repaired, updated, ok := RepairMigratedCursorFailMode(raw, record)
			if !ok {
				t.Fatal("a recorded rewrite was not repaired")
			}
			if want := strings.Replace(body, "hook_fail_mode: open", "hook_fail_mode: closed", 1); string(repaired) != want {
				t.Fatalf("repaired config:\n%s\nwant:\n%s", repaired, want)
			}
			if len(updated.Repaired) != 1 || updated.Repaired[0].To != path || updated.Repaired[0].Value != "closed" ||
				updated.ResultSHA256 != cfgtxn.SHA256Hex(repaired) || len(updated.Moved) != 1 {
				t.Fatalf("record = %+v", updated)
			}
			if note := MigratedCursorFailModeRepairNote(updated.Repaired[0]); note != "restored "+path+
				" to closed: the 1.0.x v9 migration had rewritten it to open (not an admin choice)" {
				t.Fatalf("note = %q", note)
			}
			if _, _, again := RepairMigratedCursorFailMode(repaired, updated); again {
				t.Fatal("the repair ran twice")
			}
			// The administrator opens it after the repair: it stays open.
			adminOpen := []byte(strings.Replace(string(repaired), "hook_fail_mode: closed", "hook_fail_mode: open", 1))
			if _, _, again := RepairMigratedCursorFailMode(adminOpen, updated); again {
				t.Fatal("an administrator open set after the repair was undone")
			}
		})
	}
}

func TestRepairMigratedCursorFailModeNeedsTheRecord(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	t.Setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "")
	type input struct {
		raw    []byte
		record MigrationRecord
	}
	migrated := func(body string, edit func(*MigrationRecord)) input {
		raw, record := migratedByOldRelease(t, body, migratedCursorConnectorFailMode)
		if edit != nil {
			edit(&record)
		}
		return input{raw, record}
	}
	cases := map[string]input{
		"no record":  {[]byte(managedCursorConnectorOpen), MigrationRecord{}},
		"no rewrite": migrated(managedCursorConnectorOpen, func(r *MigrationRecord) { r.Moved = nil }),
		"rewrite to closed": migrated(managedCursorConnectorOpen, func(r *MigrationRecord) {
			r.Moved[0].Value = "closed"
		}),
		"pending": migrated(managedCursorConnectorOpen, func(r *MigrationRecord) { r.Pending = true }),
		"administrator wrote it since": {[]byte(managedCursorConnectorOpen + "update:\n  check: false\n"),
			migrated(managedCursorConnectorOpen, nil).record},
		"per-user": migrated(strings.Replace(managedCursorConnectorOpen,
			"deployment_mode: managed_enterprise\nenterprise:\n  profile: standalone\n", "", 1), nil),
		"secure client": migrated(strings.Replace(managedCursorConnectorOpen,
			"profile: standalone", "profile: secure_client", 1), nil),
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, ok := RepairMigratedCursorFailMode(tc.raw, tc.record); ok {
				t.Fatal("repaired without proof of a migration rewrite")
			}
		})
	}
}

// G-small loop round 2: a migration-v9.json that decodes without the fields
// every release writes is not a record. {} and null decoded to a zero record,
// which the repair read as nothing to repair, so ensure reported compliance
// while the Cursor fail mode stayed open. Each required field, a value that
// is not a JSON object and a repaired entry the repair never writes are
// refused; every record a release writes decodes, with a BOM, pending,
// repaired, or with a field a later release adds.
func TestDecodeMigrationRecordRefusesAnInvalidRecord(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	t.Setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "")
	raw, record := migratedByOldRelease(t, managedCursorConnectorOpen, migratedCursorConnectorFailMode)
	encode := func(edit func(map[string]any)) []byte {
		t.Helper()
		encoded, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]any
		if err := json.Unmarshal(encoded, &fields); err != nil {
			t.Fatal(err)
		}
		edit(fields)
		encoded, err = json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	set := func(key string, value any) []byte { return encode(func(m map[string]any) { m[key] = value }) }
	drop := func(key string) []byte { return encode(func(m map[string]any) { delete(m, key) }) }
	repairedEntry := func(entry map[string]any) []byte { return set("repaired", []any{entry}) }
	for name, body := range map[string][]byte{
		"empty":                    nil,
		"null":                     []byte("null"),
		"empty object":             []byte("{}"),
		"unknown fields only":      []byte(`{"note":"x"}`),
		"an array":                 []byte(`[]`),
		"a string":                 []byte(`"migration"`),
		"trailing data":            append(set("actor", "lifecycle"), []byte(" {}")...),
		"no schema_version":        drop("schema_version"),
		"schema_version 0":         set("schema_version", 0),
		"no to_version":            drop("to_version"),
		"to_version 8":             set("to_version", 8),
		"no from_version":          drop("from_version"),
		"from_version 10":          set("from_version", 10),
		"no migrated_at":           drop("migrated_at"),
		"migrated_at not a time":   set("migrated_at", "yesterday"),
		"no actor":                 drop("actor"),
		"another actor":            set("actor", "admin"),
		"no source_sha256":         drop("source_sha256"),
		"short source_sha256":      set("source_sha256", "abc"),
		"no result_sha256":         drop("result_sha256"),
		"result_sha256 not hex":    set("result_sha256", strings.Repeat("z", 64)),
		"empty repaired entry":     repairedEntry(map[string]any{}),
		"repaired to open":         repairedEntry(map[string]any{"source": "repair", "from": migratedCursorConnectorFailMode, "to": migratedCursorConnectorFailMode, "value": "open"}),
		"repaired another key":     repairedEntry(map[string]any{"source": "repair", "from": "guardrail.mode", "to": "guardrail.mode", "value": "closed"}),
		"repaired by another step": repairedEntry(map[string]any{"source": "config", "from": migratedGlobalFailMode, "to": migratedGlobalFailMode, "value": "closed"}),
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := DecodeMigrationRecord(body); err == nil {
				t.Fatalf("decoded %q as %+v; want an error", body, got)
			}
		})
	}

	_, repairedRecord, ok := RepairMigratedCursorFailMode(raw, record)
	if !ok {
		t.Fatal("the recorded rewrite was not repaired")
	}
	repaired, err := json.Marshal(repairedRecord)
	if err != nil {
		t.Fatal(err)
	}
	pending := record
	pending.Pending = true
	pendingRaw, err := json.Marshal(pending)
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{
		"as migrated":       encode(func(map[string]any) {}),
		"with a BOM":        append([]byte("\xef\xbb\xbf"), encode(func(map[string]any) {})...),
		"pending":           pendingRaw,
		"repaired":          repaired,
		"a later field":     set("later_release_field", true),
		"a later schema":    set("schema_version", MigrationRecordSchemaVersion+1),
		"already on 9":      set("from_version", 9),
		"upper-case digest": set("source_sha256", strings.Repeat("A", 64)),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := DecodeMigrationRecord(body)
			if err != nil {
				t.Fatalf("decode %s: %v", body, err)
			}
			if got.ResultSHA256 == "" || got.ToVersion != ConfigVersionV9 {
				t.Fatalf("decoded %+v", got)
			}
		})
	}
	// The record decoded as written still proves the rewrite.
	decoded, err := DecodeMigrationRecord(encode(func(map[string]any) {}))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := RepairMigratedCursorFailMode(raw, decoded); !ok {
		t.Fatal("the decoded record no longer proves the rewrite")
	}
}
