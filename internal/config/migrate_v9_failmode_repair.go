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
	"bytes"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config/internal/cfgtxn"
)

// The Cursor fail-mode paths the 1.0.0-1.0.2 config_version 9 migration
// rewrote from the guardrail mode on managed standalone configs too
// (normalizeCursorFailMode, observe -> "open"). It recorded each rewrite as a
// moved entry, and only when the value changed.
const (
	migratedCursorConnectorFailMode = "guardrail.connectors.cursor.hook_fail_mode"
	migratedGlobalFailMode          = "guardrail.hook_fail_mode"
)

// RepairMigratedCursorFailMode sets a managed standalone Cursor hook fail
// mode that the 1.0.0-1.0.2 migration rewrote to "open" back to "closed".
// Those releases ran managed hooks closed whatever the value, so the "open"
// had no effect; managed hosts now honour an explicit open, and that one is
// not the administrator's. raw is the installed config.yaml and record its
// migration-v9.json. The repair applies only when the record proves it: a
// committed record with a moved "open" at the path, nothing repaired yet,
// and raw still exactly the migration's result (any later administrator
// write changes that), on a managed document that is not Secure Client. It
// returns the repaired config and the record to store with it (Repaired
// filled, ResultSHA256 the repaired bytes), so it runs once; ok is false
// when there is nothing to repair.
func RepairMigratedCursorFailMode(raw []byte, record MigrationRecord) (repaired []byte, updated MigrationRecord, ok bool) {
	if record.Pending || len(record.Repaired) > 0 || !strings.EqualFold(record.ResultSHA256, cfgtxn.SHA256Hex(raw)) {
		return nil, record, false
	}
	rewritten := map[string]bool{}
	for _, move := range record.Moved {
		value, _ := move.Value.(string)
		if move.Source == "config" && move.From == move.To &&
			(move.To == migratedCursorConnectorFailMode || move.To == migratedGlobalFailMode) &&
			strings.EqualFold(strings.TrimSpace(value), "open") {
			rewritten[move.To] = true
		}
	}
	if len(rewritten) == 0 {
		return nil, record, false
	}
	var doc yaml.Node
	if yaml.Unmarshal(raw, &doc) != nil {
		return nil, record, false
	}
	root := v8DocumentRoot(&doc)
	if root == nil || !v9ManagedDocument(root) || v9SecureClientDocument(root) {
		return nil, record, false
	}
	var moves []MigrationMove
	restore := func(node *yaml.Node, path string) {
		if rewritten[path] && node != nil && node.Kind == yaml.ScalarNode &&
			strings.EqualFold(strings.TrimSpace(node.Value), "open") {
			node.Value = "closed"
			moves = append(moves, MigrationMove{Source: "repair", From: path, To: path, Value: "closed"})
			rewritten[path] = false
		}
	}
	guardrail := v8YAMLMapValue(root, "guardrail")
	if connectors := v8YAMLMapValue(guardrail, "connectors"); connectors != nil && connectors.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(connectors.Content); i += 2 {
			if normalizeConnectorKey(connectors.Content[i].Value) == "cursor" {
				restore(v8YAMLMapValue(connectors.Content[i+1], "hook_fail_mode"), migratedCursorConnectorFailMode)
			}
		}
	}
	if normalizeConnectorKey(yamlScalarValue(v8YAMLMapValue(guardrail, "connector"))) == "cursor" {
		restore(v8YAMLMapValue(guardrail, "hook_fail_mode"), migratedGlobalFailMode)
	}
	if len(moves) == 0 {
		return nil, record, false
	}
	// The same encoder as the migration, so only the restored values change.
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if enc.Encode(&doc) != nil || enc.Close() != nil {
		return nil, record, false
	}
	updated = record
	updated.Repaired = moves
	updated.ResultSHA256 = cfgtxn.SHA256Hex(out.Bytes())
	return out.Bytes(), updated, true
}

// MigratedCursorFailModeRepairNote is the ensure change line for one value
// RepairMigratedCursorFailMode restored.
func MigratedCursorFailModeRepairNote(move MigrationMove) string {
	return fmt.Sprintf("restored %s to closed: the 1.0.x v9 migration had rewritten it to open (not an admin choice)", move.To)
}

// WriteMigrationRecord replaces migration-v9.json next to configPath.
func WriteMigrationRecord(configPath string, record MigrationRecord) error {
	return writeMigrationRecord(MigrationRecordPath(configPath), record)
}
