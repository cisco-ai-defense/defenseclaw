// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"

	"gopkg.in/yaml.v3"
)

// V8ManagedChecksView is raw as the managed config_version 8 checks read
// it. The per-user CLI of 1.0.x wrote a top-level update_check, which the v8
// schema never declared and the v9 migration moves to update.check. The v8
// checks refused it as an unknown setting before the migration ran, so a
// managed v8 file that `config migrate` handles was refused by ensure on
// Linux and macOS and by Windows Setup's config check (rel-1-0-2 GAP-0145).
// Both lifecycles check a candidate through this view; the per-user `config
// validate` keeps refusing the key with its migrate hint.
//
// The view blanks that one line, so every other line keeps its number; the
// migration reads raw and the migrated file is checked as v9 (update.check
// must be a boolean). A value that does not fit on the key's line is left
// for the v8 checks to refuse as before. Remove with the v8 to v9 migration.
func V8ManagedChecksView(raw []byte) []byte {
	if !NeedsMigrationV9(raw) {
		return raw
	}
	var doc yaml.Node
	if yaml.Unmarshal(raw, &doc) != nil || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return raw
	}
	root := doc.Content[0]
	for i := 0; i+1 < len(root.Content); i += 2 {
		key, value := root.Content[i], root.Content[i+1]
		if key.Value != "update_check" {
			continue
		}
		if value.Kind != yaml.ScalarNode || value.Line != key.Line {
			return raw
		}
		lines := bytes.SplitAfter(raw, []byte("\n"))
		n := key.Line - 1
		if n < 0 || n >= len(lines) {
			return raw
		}
		line := lines[n]
		ending := line[len(bytes.TrimRight(line, "\r\n")):]
		lines[n] = append([]byte(nil), ending...)
		return bytes.Join(lines, nil)
	}
	return raw
}
