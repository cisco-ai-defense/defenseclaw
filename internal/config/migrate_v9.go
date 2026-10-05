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
	"context"
	"errors"
)

// The v8 to v9 migration moves admin intent into config.yaml: data.json
// admission and guardrail values, the *_actions keys,
// watch.allow_list_bypass_scan, rule_pack_dir, the v8 scanner keys,
// update_check and (OSS only) the operator block/allow rows of audit.db.
// It is the one implementation: `defenseclaw-gateway config migrate --to 9`,
// the Python CONFIG_MIGRATIONS[9] step and enterprise ensure all call it,
// and the gateway runs it in memory (read-only) on a v8 file at load.

// Files the migration writes next to config.yaml or under policy_dir.
const (
	// MigrationV9RecordFile is the evidence record (MigrationRecord).
	MigrationV9RecordFile = "migration-v9.json"
	// ConfigV8BackupSuffix is appended to config.yaml for the pre-migration
	// bytes, which the upgrade rollback restores.
	ConfigV8BackupSuffix = ".v8.bak"
	// DataJSONMigratedSuffix is appended to <policy_dir>/rego/data.json
	// once its values have moved into config.
	DataJSONMigratedSuffix = ".migrated-v9"
)

// MigrationRecordSchemaVersion versions the migration-v9.json shape.
const MigrationRecordSchemaVersion = 1

// ErrMigrateV9NotImplemented is returned until the migration lands.
var ErrMigrateV9NotImplemented = errors.New("config: the config_version 9 migration is not implemented yet")

// MigrateV9Input names the migration inputs.
type MigrateV9Input struct {
	// ConfigPath is the v8 config.yaml.
	ConfigPath string
	// Source is the v8 bytes; when nil they are read from ConfigPath.
	Source []byte
	// DataJSONPath is <policy_dir>/rego/data.json; "" or missing is skipped.
	DataJSONPath string
	// AuditDBPath is audit.db, whose operator actions rows move into
	// asset_policy. Empty skips them; managed standalone always skips them
	// and reports the count as a local_enforcement_entries_ignored warning.
	AuditDBPath string
	// Managed is true on StandaloneEnterprise() hosts.
	Managed bool
	// DryRun computes the result without writing anything.
	DryRun bool
	// InMemory migrates for a read-only load: nothing is written and
	// audit.db is not touched.
	InMemory bool
}

// MigrateV9Result is the outcome of one migration.
type MigrateV9Result struct {
	// Migrated is the config_version 9 document.
	Migrated []byte
	// Record is the evidence written to MigrationV9RecordFile.
	Record MigrationRecord
	// Written lists the files written (empty for DryRun and InMemory).
	Written []string
}

// MigrationRecord is migration-v9.json: every value moved and every
// conflict. Values are rendered without secrets.
type MigrationRecord struct {
	SchemaVersion int    `json:"schema_version"`
	FromVersion   int    `json:"from_version"`
	ToVersion     int    `json:"to_version"`
	MigratedAt    string `json:"migrated_at"`
	// Actor is "migration" or "lifecycle".
	Actor string `json:"actor"`
	// SourceSHA256 and ResultSHA256 are the config bytes before and after.
	SourceSHA256 string `json:"source_sha256"`
	ResultSHA256 string `json:"result_sha256"`
	// Moved lists every value written to a v9 key.
	Moved []MigrationMove `json:"moved"`
	// Conflicts lists values that disagreed; data.json wins over the
	// *_actions keys because enforcement read it.
	Conflicts []MigrationConflict `json:"conflicts"`
	// Removed lists v8 keys dropped without a v9 value (no reader).
	Removed []string `json:"removed,omitempty"`
	// ActionsRowsMoved counts audit.db actions rows moved to asset_policy.
	ActionsRowsMoved int `json:"actions_rows_moved"`
	// ActionsRowsIgnored counts rows left in place on a managed host.
	ActionsRowsIgnored int `json:"actions_rows_ignored,omitempty"`
	// Notes are behaviour changes the operator should know about (for
	// example block_at now applies on every path).
	Notes []string `json:"notes,omitempty"`
	// Acknowledged is set by `defenseclaw config migrate --ack`.
	Acknowledged bool `json:"acknowledged,omitempty"`
}

// MigrationMove is one value moved from a v8 source to a v9 key.
type MigrationMove struct {
	// Source is "config", "data.json" or "audit.db".
	Source string `json:"source"`
	// From is the source path, for example skill_actions.high or
	// data.json:config.scan_on_install or actions:<id>.
	From string `json:"from"`
	// To is the v9 config path.
	To string `json:"to"`
	// Value is the display-safe value written.
	Value any `json:"value,omitempty"`
}

// MigrationConflict is a v9 key with disagreeing v8 sources.
type MigrationConflict struct {
	To     string `json:"to"`
	Kept   string `json:"kept"`
	Lost   string `json:"lost"`
	Reason string `json:"reason"`
}

// MigrateV9 migrates a config_version 8 source to config_version 9.
func MigrateV9(ctx context.Context, in MigrateV9Input) (*MigrateV9Result, error) {
	_ = ctx
	_ = in
	return nil, ErrMigrateV9NotImplemented
}
