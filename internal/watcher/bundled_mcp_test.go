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

package watcher

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnumerateTargetsSkipsBundledCodexMCP(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	codexHome := filepath.Join(t.TempDir(), "codex-home")
	t.Setenv("CODEX_HOME", codexHome)
	if err := os.MkdirAll(codexHome, 0o700); err != nil {
		t.Fatal(err)
	}
	body := `[mcp_servers.openaiDeveloperDocs]
url = "https://developers.openai.com/mcp"

[mcp_servers.operator]
command = "operator-mcp"
`
	if err := os.WriteFile(filepath.Join(codexHome, "config.toml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Guardrail.Connector = "codex"

	targets := New(cfg, []string{skillDir}, nil, store, logger, nil, nil, nil).enumerateTargets()
	seen := map[string]bool{}
	for _, target := range targets {
		if target.Type == InstallMCP {
			seen[target.Name] = true
		}
	}
	if seen["openaiDeveloperDocs"] {
		t.Fatalf("bundled Codex MCP reached watcher targets: %+v", targets)
	}
	if !seen["operator"] {
		t.Fatalf("operator Codex MCP missing from watcher targets: %+v", targets)
	}
}
