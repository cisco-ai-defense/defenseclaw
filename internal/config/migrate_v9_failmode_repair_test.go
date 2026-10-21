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
