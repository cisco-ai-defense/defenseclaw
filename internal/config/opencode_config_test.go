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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func TestReadMCPServersOpenCodeRejectsOversizedWorkspaceLayerAcrossRescans(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	t.Setenv("OPENCODE_CONFIG", "")
	t.Setenv("OPENCODE_CONFIG_DIR", "")
	t.Setenv("OPENCODE_CONFIG_CONTENT", "")

	globalDir := filepath.Join(home, ".config", "opencode")
	if err := os.MkdirAll(globalDir, 0o700); err != nil {
		t.Fatal(err)
	}
	globalPath := filepath.Join(globalDir, "opencode.jsonc")
	if err := os.WriteFile(globalPath, []byte(`{
		// Keep normal JSONC parsing and precedence intact.
		"mcp": {"shared": {"command": ["global"]},},
	}`), 0o600); err != nil {
		t.Fatal(err)
	}

	workspace := filepath.Join(home, "workspace")
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	oversized := `{
		// This is valid JSONC but must never be parsed because it exceeds the inventory limit.
		"mcp": {"shared": {"command": ["oversized-workspace"]},},
		"padding": "` + strings.Repeat("x", int(maxOpenCodeInventoryConfigBytes)) + `",
	}`
	if err := os.WriteFile(filepath.Join(workspace, "opencode.jsonc"), []byte(oversized), 0o600); err != nil {
		t.Fatal(err)
	}

	for scan := 0; scan < 8; scan++ {
		entries, err := readMCPServersOpenCode(workspace)
		if err != nil {
			t.Fatalf("scan %d: read OpenCode MCP layers: %v", scan, err)
		}
		if len(entries) != 1 {
			t.Fatalf("scan %d: entries = %+v, want the safe global layer only", scan, entries)
		}
		entry := entries[0]
		if entry.Name != "shared" || entry.Command != "global" || entry.Source != globalPath || entry.SourceScope != "global" {
			t.Fatalf("scan %d: entry = %+v, want stable global fallback", scan, entry)
		}
	}
}
