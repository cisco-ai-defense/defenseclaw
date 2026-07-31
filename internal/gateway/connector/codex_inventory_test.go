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

package connector

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestCodexProjectLayerDirsHonorsConfiguredRootMarkers(t *testing.T) {
	root := t.TempDir()
	active := filepath.Join(root, "packages", "service")
	if err := os.MkdirAll(active, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".sl"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	codexHome := filepath.Join(root, "codex-home")
	if err := os.MkdirAll(codexHome, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(codexHome, "config.toml"),
		[]byte(`project_root_markers = [".sl"]`+"\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CODEX_HOME", codexHome)

	got := CodexProjectLayerDirs(active)
	want := []string{active, filepath.Dir(active), root}
	if !slices.Equal(got, want) {
		t.Fatalf("project layers=%v want %v", got, want)
	}

	if err := os.WriteFile(
		filepath.Join(codexHome, "config.toml"),
		[]byte("project_root_markers = []\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if got := CodexProjectLayerDirs(active); !slices.Equal(got, []string{active}) {
		t.Fatalf("empty-marker project layers=%v want active directory only", got)
	}
}

func TestCodexProjectLayerDirsFallsBackOnUnsafeRootMarkerConfig(t *testing.T) {
	root := t.TempDir()
	middle := filepath.Join(root, "packages")
	active := filepath.Join(middle, "service")
	codexHome := filepath.Join(root, "codex-home")
	for _, dir := range []string{filepath.Join(root, ".git"), active, codexHome} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(middle, ".sl"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	oversized := make([]byte, codexMarketplaceMaxBytes+1)
	copy(oversized, `project_root_markers = [".sl"]`)
	if err := os.WriteFile(filepath.Join(codexHome, "config.toml"), oversized, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CODEX_HOME", codexHome)

	want := []string{active, middle, root}
	if got := CodexProjectLayerDirs(active); !slices.Equal(got, want) {
		t.Fatalf("unsafe root-marker config layers=%v want documented .git fallback %v", got, want)
	}
}

func TestCodexComponentTargetsUseOfficialCurrentLayouts(t *testing.T) {
	home := t.TempDir()
	codexHome := filepath.Join(home, "custom-codex")
	repo := filepath.Join(home, "repo")
	active := filepath.Join(repo, "packages", "service")
	for _, dir := range []string{
		codexHome,
		filepath.Join(repo, ".git"),
		active,
		filepath.Join(home, "personal-plugin"),
		filepath.Join(repo, "plugins", "repo-plugin"),
		filepath.Join(repo, "plugins", "legacy-plugin"),
		filepath.Join(home, ".agents", "plugins"),
		filepath.Join(repo, ".agents", "plugins"),
		filepath.Join(repo, ".claude-plugin"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(
		filepath.Join(codexHome, "config.toml"),
		[]byte(`project_root_markers = [".git"]`+"\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(home, ".agents", "plugins", "marketplace.json"),
		[]byte(`{"plugins":[
			{"source":{"source":"local","path":"./personal-plugin"}},
			{"source":{"source":"local","path":"./../escape"}},
			{"source":{"source":"url","path":"./remote"}}
		]}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(repo, ".agents", "plugins", "marketplace.json"),
		[]byte(`{"plugins":[{"source":"./plugins/repo-plugin"}]}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(repo, ".claude-plugin", "marketplace.json"),
		[]byte(`{"plugins":[{"source":{"source":"local","path":"./plugins/legacy-plugin"}}]}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CODEX_HOME", codexHome)

	if err := WithUserHomeDir(home, func() error {
		wantMarketplaceOrder := []string{
			filepath.Join(repo, "plugins", "repo-plugin"),
			filepath.Join(repo, "plugins", "legacy-plugin"),
			filepath.Join(home, "personal-plugin"),
		}
		if got := CodexPluginSourceDirs(active); !slices.Equal(got, wantMarketplaceOrder) {
			t.Errorf("marketplace source order=%v want repo, legacy repo, personal %v", got, wantMarketplaceOrder)
		}
		targets := NewCodexConnector().ComponentTargets(active)
		for component, want := range map[string]string{
			"skill": filepath.Join(home, ".agents", "skills"),
			"mcp":   filepath.Join(active, ".codex", "config.toml"),
			"agent": filepath.Join(active, ".codex", "agents"),
			"rule":  filepath.Join(active, ".codex", "rules"),
		} {
			if !slices.Contains(targets[component], want) {
				t.Errorf("%s targets=%v missing %q", component, targets[component], want)
			}
		}
		for _, want := range []string{
			filepath.Join(home, "personal-plugin"),
			filepath.Join(repo, "plugins", "repo-plugin"),
			filepath.Join(repo, "plugins", "legacy-plugin"),
			filepath.Join(codexHome, "plugins", "cache"),
		} {
			if !slices.Contains(targets["plugin"], want) {
				t.Errorf("plugin targets=%v missing %q", targets["plugin"], want)
			}
		}
		for _, stale := range []string{
			filepath.Join(active, ".codex", "skills"),
			filepath.Join(active, ".mcp.json"),
			filepath.Join(active, ".codex", "plugins"),
			filepath.Join(filepath.Dir(home), "escape"),
		} {
			for component, paths := range targets {
				if slices.Contains(paths, stale) {
					t.Errorf("%s targets retained unsupported/unsafe path %q: %v", component, stale, paths)
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCodexMarketplaceReaderRejectsSymlinkAndOversizedInput(t *testing.T) {
	root := t.TempDir()

	t.Run("oversized", func(t *testing.T) {
		oversized := filepath.Join(root, "oversized.json")
		payload := make([]byte, codexMarketplaceMaxBytes+1)
		copy(payload, `{"plugins":[]}`)
		if err := os.WriteFile(oversized, payload, 0o600); err != nil {
			t.Fatal(err)
		}
		if got := codexMarketplaceLocalSources(oversized, root); len(got) != 0 {
			t.Fatalf("oversized marketplace resolved sources: %v", got)
		}
	})

	t.Run("symlink", func(t *testing.T) {
		valid := filepath.Join(root, "valid.json")
		if err := os.WriteFile(valid, []byte(`{"plugins":[{"source":"./plugin"}]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(root, "marketplace.json")
		if err := os.Symlink(valid, link); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		if got := codexMarketplaceLocalSources(link, root); len(got) != 0 {
			t.Fatalf("symlink marketplace resolved sources: %v", got)
		}
	})

	t.Run("symlink source directory", func(t *testing.T) {
		realSource := filepath.Join(root, "real-plugin")
		if err := os.MkdirAll(realSource, 0o755); err != nil {
			t.Fatal(err)
		}
		linkSource := filepath.Join(root, "linked-plugin")
		if err := os.Symlink(realSource, linkSource); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		marketplace := filepath.Join(root, "source-marketplace.json")
		if err := os.WriteFile(
			marketplace,
			[]byte(`{"plugins":[{"source":"./linked-plugin"}]}`),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
		if got := codexMarketplaceLocalSources(marketplace, root); len(got) != 0 {
			t.Fatalf("symlink source directory resolved sources: %v", got)
		}
	})
}
