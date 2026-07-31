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

package gateway

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func TestCodexComponentTargetsExpandCurrentOfficialFiles(t *testing.T) {
	home := t.TempDir()
	codexHome := filepath.Join(home, "codex-home")
	repo := filepath.Join(home, "repo")
	active := filepath.Join(repo, "packages", "service")
	paths := []string{
		filepath.Join(home, ".agents", "skills", "personal-skill"),
		filepath.Join(codexHome, "plugins", "cache", "market", "installed-plugin", "local"),
		filepath.Join(codexHome, "agents"),
		filepath.Join(codexHome, "rules"),
		filepath.Join(repo, ".git"),
		filepath.Join(repo, ".agents", "skills", "repo-skill"),
		filepath.Join(repo, ".agents", "plugins"),
		filepath.Join(repo, "plugins", "source-plugin"),
		filepath.Join(repo, ".codex", "agents"),
		filepath.Join(repo, ".codex", "rules"),
		filepath.Join(repo, ".codex"),
		active,
	}
	for _, path := range paths {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		filepath.Join(codexHome, "config.toml"):              `project_root_markers = [".git"]` + "\n",
		filepath.Join(codexHome, "agents", "personal.toml"):  `name = "personal"` + "\n",
		filepath.Join(codexHome, "rules", "personal.rules"):  `prefix_rule(pattern=["git"])` + "\n",
		filepath.Join(repo, ".codex", "config.toml"):         `[mcp_servers.fs]` + "\n",
		filepath.Join(repo, ".codex", "agents", "repo.toml"): `name = "repo"` + "\n",
		filepath.Join(repo, ".codex", "rules", "repo.rules"): `prefix_rule(pattern=["go"])` + "\n",
		filepath.Join(repo, ".agents", "plugins", "marketplace.json"): `{
			"plugins":[{"source":{"source":"local","path":"./plugins/source-plugin"}}]
		}`,
	}
	for path, body := range files {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("CODEX_HOME", codexHome)

	if err := connector.WithUserHomeDir(home, func() error {
		targets := codexComponentTargets(active)
		expected := map[string][]string{
			"skill": {
				filepath.Join(home, ".agents", "skills", "personal-skill"),
				filepath.Join(repo, ".agents", "skills", "repo-skill"),
			},
			"plugin": {
				filepath.Join(codexHome, "plugins", "cache", "market", "installed-plugin", "local"),
				filepath.Join(repo, "plugins", "source-plugin"),
			},
			"mcp": {
				filepath.Join(codexHome, "config.toml"),
				filepath.Join(repo, ".codex", "config.toml"),
			},
			"agent": {
				filepath.Join(codexHome, "agents", "personal.toml"),
				filepath.Join(repo, ".codex", "agents", "repo.toml"),
			},
			"rule": {
				filepath.Join(codexHome, "rules", "personal.rules"),
				filepath.Join(repo, ".codex", "rules", "repo.rules"),
			},
		}
		for component, wants := range expected {
			for _, want := range wants {
				if !slices.Contains(targets[component], want) {
					t.Errorf("%s targets=%v missing %q", component, targets[component], want)
				}
			}
		}
		for _, stale := range []string{
			filepath.Join(repo, ".codex", "skills"),
			filepath.Join(repo, ".mcp.json"),
			filepath.Join(repo, ".codex", "plugins"),
		} {
			for component, got := range targets {
				if slices.Contains(got, stale) {
					t.Errorf("%s targets retained unsupported path %q: %v", component, stale, got)
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
