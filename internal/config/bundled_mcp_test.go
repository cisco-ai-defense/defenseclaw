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
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

const (
	codexDocsMCPName = "openaiDeveloperDocs"
	codexDocsMCPURL  = "https://developers.openai.com/mcp"
)

func TestCodexBundledMCPProvenanceIsExactAndUserScoped(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	codexHome := filepath.Join(home, ".codex")
	t.Setenv("CODEX_HOME", codexHome)
	if err := os.MkdirAll(codexHome, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(codexHome, "config.toml")
	body := `[mcp_servers.openaiDeveloperDocs]
url = "https://developers.openai.com/mcp"

[mcp_servers.node_repl]
command = "node_repl"
args = []

[mcp_servers.node_repl.env]
CODEX_HOME = "operator-state"
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	entries, err := ReadMCPFromCodexUserConfigTOML(path)
	if err != nil {
		t.Fatal(err)
	}
	byName := mcpEntriesByName(entries)
	if !byName[codexDocsMCPName].Bundled {
		t.Fatalf("exact user docs entry = %+v, want bundled", byName[codexDocsMCPName])
	}
	if byName["node_repl"].Bundled {
		t.Fatalf("node_repl = %+v, want scan-eligible", byName["node_repl"])
	}

	generic, err := ReadMCPFromCodexConfigTOML(path)
	if err != nil {
		t.Fatal(err)
	}
	if mcpEntriesByName(generic)[codexDocsMCPName].Bundled {
		t.Fatal("generic/project reader must not assert user-scope bundled provenance")
	}
}

func TestCodexDocsMCPWithExtraFieldIsScanEligible(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	body := `[mcp_servers.openaiDeveloperDocs]
url = "https://developers.openai.com/mcp"
http_headers = { Authorization = "operator-controlled" }
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := ReadMCPFromCodexUserConfigTOML(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Bundled {
		t.Fatalf("modified docs entry = %+v, want scan-eligible", entries)
	}
}

func TestAMPSkillMCPDoesNotInheritCodexBundledIdentity(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	skill := filepath.Join(home, ".config", "agents", "skills", "docs")
	if err := os.MkdirAll(skill, 0o700); err != nil {
		t.Fatal(err)
	}
	body := `{"openaiDeveloperDocs":{"url":"https://developers.openai.com/mcp"}}`
	if err := os.WriteFile(filepath.Join(skill, "mcp.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	entries, err := readMCPServersAMP("")
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := mcpEntriesByName(entries)[codexDocsMCPName]
	if !ok {
		t.Fatalf("Amp skill MCP missing from entries: %+v", entries)
	}
	if entry.Bundled {
		t.Fatalf("Amp skill MCP = %+v, must remain scan-eligible", entry)
	}
}
