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
	"runtime"
	"slices"
	"testing"
)

func TestReadUserMCPServersForConnectorSkipsProjectScopes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the sandbox MCP inventory serves Linux and macOS sandboxes; Windows finds the profile through USERPROFILE, not HOME")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	t.Setenv("CODEX_HOME", filepath.Join(home, ".codex"))
	project := filepath.Join(home, "proj")
	for path, body := range map[string]string{
		filepath.Join(home, ".claude.json"): `{"mcpServers":{"user-srv":{"command":"npx"}},` +
			`"projects":{"` + project + `":{"mcpServers":{"local-srv":{"command":"x"}}}}}`,
		filepath.Join(project, ".mcp.json"):                      `{"mcpServers":{"repo-srv":{"command":"y"}}}`,
		filepath.Join(home, ".codex", "config.toml"):             "[mcp_servers.codex-user]\ncommand = \"npx\"\n",
		filepath.Join(project, ".codex", "config.toml"):          "[mcp_servers.codex-repo]\ncommand = \"z\"\n",
		filepath.Join(home, ".claude", "settings.json"):          `{"mcpServers":{"settings-srv":{"command":"s"}}}`,
		filepath.Join(project, ".claude", "settings.json"):       `{"mcpServers":{"repo-settings":{"command":"r"}}}`,
		filepath.Join(project, ".claude", "settings.local.json"): `{}`,
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(project)
	names := func(connector string) []string {
		t.Helper()
		entries, err := ReadUserMCPServersForConnector(connector)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, e := range entries {
			out = append(out, e.Name)
		}
		slices.Sort(out)
		return out
	}
	if got := names("claudecode"); !slices.Equal(got, []string{"settings-srv", "user-srv"}) {
		t.Fatalf("claudecode user MCP servers = %v", got)
	}
	if got := names("codex"); !slices.Equal(got, []string{"codex-user"}) {
		t.Fatalf("codex user MCP servers = %v", got)
	}
	if _, err := ReadUserMCPServersForConnector("opencode"); err == nil {
		t.Fatal("opencode has no sandbox MCP inventory")
	}
}
