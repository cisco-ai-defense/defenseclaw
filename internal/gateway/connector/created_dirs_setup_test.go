// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// createdDirsConnector writes its config file below the home on Setup and a
// disabled hook script into the data directory on Teardown.
type createdDirsConnector struct {
	stubConnector
	config string
}

func (c *createdDirsConnector) HookScriptNames(SetupOpts) []string { return []string{"fake-hook.sh"} }
func (c *createdDirsConnector) HookCapabilities(SetupOpts) HookCapability {
	return HookCapability{ConfigPath: c.config}
}
func (c *createdDirsConnector) Setup(context.Context, SetupOpts) error {
	if err := os.MkdirAll(filepath.Dir(c.config), 0o700); err != nil {
		return err
	}
	return os.WriteFile(c.config, []byte("{}"), 0o600)
}
func (c *createdDirsConnector) Teardown(_ context.Context, opts SetupOpts) error {
	_ = os.Remove(c.config)
	if err := os.MkdirAll(filepath.Join(opts.DataDir, "hooks"), 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(opts.DataDir, "hooks", "fake-hook.sh"), []byte("exit 0\n"), 0o700)
}

func TestSetupRecordingCreatedDirsRecordsConfigParents(t *testing.T) {
	home := t.TempDir()
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := os.Mkdir(filepath.Join(home, ".agent"), 0o700); err != nil {
		t.Fatal(err)
	}
	conn := &createdDirsConnector{stubConnector: stubConnector{name: "fake"}, config: filepath.Join(home, ".agent", "hooks", "deep", "hooks.json")}
	err := WithUserHomeDir(home, func() error {
		return SetupRecordingCreatedDirs(context.Background(), conn, SetupOpts{DataDir: dataDir})
	})
	if err != nil {
		t.Fatal(err)
	}
	got := readWatcherCreatedDirs(filepath.Join(dataDir, watcherCreatedDirsFile)).Dirs
	slices.Sort(got)
	want := []string{filepath.Join(home, ".agent", "hooks"), filepath.Join(home, ".agent", "hooks", "deep")}
	if !slices.Equal(got, want) {
		t.Fatalf("recorded %v, want %v (the existing ~/.agent is not DefenseClaw's)", got, want)
	}
}

func TestRemovalLeavingNoNewDirs(t *testing.T) {
	for _, existed := range []bool{false, true} {
		home := t.TempDir()
		dataDir := filepath.Join(home, ".defenseclaw")
		if existed {
			if err := os.Mkdir(dataDir, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		conn := &createdDirsConnector{stubConnector: stubConnector{name: "fake"}, config: filepath.Join(home, ".agent", "hooks.json")}
		opts := SetupOpts{DataDir: dataDir}
		err := WithUserHomeDir(home, func() error {
			return RemovalLeavingNoNewDirs(conn, opts, func() error {
				// A removal that also makes the config folder.
				if err := os.MkdirAll(filepath.Dir(conn.config), 0o700); err != nil {
					return err
				}
				return conn.Teardown(context.Background(), opts)
			})
		})
		if err != nil {
			t.Fatal(err)
		}
		_, dataErr := os.Lstat(dataDir)
		_, agentErr := os.Lstat(filepath.Join(home, ".agent"))
		// The empty config folder the removal made goes either way (an empty
		// ~/.codex stayed after the purge on dc-ubuntu-eh).
		if !os.IsNotExist(agentErr) {
			t.Fatalf("existed %v: the empty folder the removal made stayed: %v", existed, agentErr)
		}
		if existed && dataErr != nil {
			t.Fatalf("existing data dir: the removal's files must stay: %v", dataErr)
		}
		if !existed && !os.IsNotExist(dataErr) {
			t.Fatalf("missing data dir: want no new folders, got data %v", dataErr)
		}
	}
}

// The OpenCode plugin folder is made before any Setup (the gateway's
// registration snapshot) and is not a hook config path, so it was never
// listed and stayed after uninstall --all --binaries, empty.
func TestPrepareOpenCodePluginArtifactDestinationRecordsTheFoldersItCreates(t *testing.T) {
	home := t.TempDir()
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(filepath.Join(home, ".config", "opencode"), 0o700); err != nil {
		t.Fatal(err)
	}
	plugin := filepath.Join(home, ".config", "opencode", "plugins", "defenseclaw.js")
	err := WithUserHomeDir(home, func() error { return prepareOpenCodePluginArtifactDestination(plugin, dataDir) })
	if err != nil {
		t.Fatal(err)
	}
	got := readWatcherCreatedDirs(filepath.Join(dataDir, watcherCreatedDirsFile)).Dirs
	want := []string{filepath.Join(home, ".config", "opencode", "plugins")}
	if !slices.Equal(got, want) {
		t.Fatalf("recorded %v, want %v (the existing ~/.config/opencode is OpenCode's)", got, want)
	}
	removeWatcherCreatedDirs(dataDir, filepath.Join(home, ".config", "opencode"))
	if _, err := os.Lstat(filepath.Dir(plugin)); !os.IsNotExist(err) {
		t.Fatalf("the teardown must remove the empty plugin folder: %v", err)
	}
}

// GAP-1106: an earlier release made the plugin folder for its plugin without
// listing it, so uninstall left it. A folder that holds only DefenseClaw's
// plugin (or nothing) is recorded now; one with other plugins is not.
func TestPrepareOpenCodePluginArtifactDestinationRecordsAnEarlierReleasesFolder(t *testing.T) {
	for name, entries := range map[string][]string{
		"only the plugin": {"defenseclaw.js"},
		"empty":           nil,
		"other plugins":   {"defenseclaw.js", "mine.ts"},
	} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			dataDir := filepath.Join(home, ".defenseclaw")
			plugins := filepath.Join(home, ".config", "opencode", "plugins")
			if err := os.MkdirAll(plugins, 0o700); err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if err := os.WriteFile(filepath.Join(plugins, entry), []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			plugin := filepath.Join(plugins, "defenseclaw.js")
			err := WithUserHomeDir(home, func() error { return prepareOpenCodePluginArtifactDestination(plugin, dataDir) })
			if err != nil {
				t.Fatal(err)
			}
			got := readWatcherCreatedDirs(filepath.Join(dataDir, watcherCreatedDirsFile)).Dirs
			var want []string
			if name != "other plugins" {
				want = []string{plugins}
			}
			if !slices.Equal(got, want) {
				t.Fatalf("recorded %v, want %v", got, want)
			}
		})
	}
}

// patchingConnector writes, besides its hook config, an agent file it lists
// in AgentPaths (OpenCode's opencode.json in a home where OpenCode never ran).
type patchingConnector struct {
	createdDirsConnector
	patched string
}

func (c *patchingConnector) AgentPaths(SetupOpts) AgentPaths {
	return AgentPaths{PatchedFiles: []string{c.patched}}
}

func (c *patchingConnector) Setup(ctx context.Context, opts SetupOpts) error {
	if err := os.MkdirAll(filepath.Dir(c.patched), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(c.patched, []byte("{}"), 0o600); err != nil {
		return err
	}
	return c.createdDirsConnector.Setup(ctx, opts)
}

func TestSetupRecordingCreatedDirsRecordsPatchedFileParents(t *testing.T) {
	home := t.TempDir()
	dataDir := filepath.Join(home, ".defenseclaw")
	conn := &patchingConnector{
		createdDirsConnector: createdDirsConnector{stubConnector: stubConnector{name: "fake"}, config: filepath.Join(home, ".agent", "hooks.json")},
		patched:              filepath.Join(home, ".config", "opencode", "opencode.json"),
	}
	if err := WithUserHomeDir(home, func() error {
		return SetupRecordingCreatedDirs(context.Background(), conn, SetupOpts{DataDir: dataDir})
	}); err != nil {
		t.Fatal(err)
	}
	got := readWatcherCreatedDirs(filepath.Join(dataDir, watcherCreatedDirsFile)).Dirs
	for _, want := range []string{filepath.Join(home, ".config"), filepath.Join(home, ".config", "opencode"), filepath.Join(home, ".agent")} {
		if !slices.Contains(got, want) {
			t.Fatalf("recorded %v, want it to list %s", got, want)
		}
	}
}

// The enterprise installer made ~/.copilot/hooks (and the like) before
// Setup, so Setup found them and did not list them; only Kiro kept a list.
// Every connector's now go into the created-folder list the purge clears.
func TestRecordHookConfigParentDirsListsEveryConnectorsFolders(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), ".defenseclaw")
	dir := filepath.Join(filepath.Dir(dataDir), ".copilot", "hooks")
	RecordHookConfigParentDirs("copilot", dataDir, []string{dir})
	if got := readWatcherCreatedDirs(filepath.Join(dataDir, watcherCreatedDirsFile)).Dirs; !slices.Equal(got, []string{dir}) {
		t.Fatalf("recorded %v, want %v", got, []string{dir})
	}
}
