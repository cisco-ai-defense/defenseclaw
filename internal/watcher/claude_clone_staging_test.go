// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// Issue #1428: "claude plugin update" clones the marketplace into
// <cache>/temp_subdir_<n>_<random>.clone. The watcher read each folder of its
// .git (hooks, objects, refs, info, logs) as a <marketplace>/<plugin>/<version>
// plugin named ".git@temp_subdir_<n>.clone", found no manifest and quarantined
// the git object store, so the update failed.

// cloneStagingTree builds a staging clone like Claude Code's, with a plugin
// folder of the marketplace inside it, and returns its path.
func cloneStagingTree(t *testing.T, cache, name string) string {
	t.Helper()
	clone := filepath.Join(cache, name)
	for _, dir := range []string{"hooks", "objects", "refs", "info", "logs"} {
		if err := os.MkdirAll(filepath.Join(clone, ".git", dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(clone, "plugins", "sample", ".claude-plugin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(clone, "plugins", "sample", ".claude-plugin", "plugin.json"), []byte(`{"name":"sample"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return clone
}

func transientTargets(w *InstallWatcher) []string {
	var out []string
	for _, evt := range w.enumerateTargets() {
		if evt.Type == InstallPlugin {
			out = append(out, evt.Path)
		}
	}
	return out
}

func TestClaudePluginUpdateCloneIsNotAPlugin(t *testing.T) {
	for _, tc := range []struct {
		name      string
		connector string
		home      string
	}{
		{"claude code cache", "claudecode", ".claude"},
		{"codex cache", "codex", ".codex"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, store, logger, _ := setupTestEnv(t)
			cfg.Guardrail.Connector = tc.connector
			cache := filepath.Join(t.TempDir(), tc.home, "plugins", "cache")
			clone := cloneStagingTree(t, cache, "temp_subdir_1793946491108_t2ymk0.clone")
			// A plugin the agent really loads, one with its own .git folder
			// inside the version folder, stays a plugin.
			real := filepath.Join(cache, "mkt", "real", "1.0.0")
			if err := os.MkdirAll(filepath.Join(real, ".git", "objects"), 0o700); err != nil {
				t.Fatal(err)
			}
			w := New(cfg, nil, []string{cache}, store, logger, nil, nil)

			if got := transientTargets(w); len(got) != 1 || !sameWatcherPath(got[0], real) {
				t.Fatalf("rescan targets %v, want only %s", got, real)
			}

			// The live watcher reads the same folders as it is told of them.
			for _, path := range []string{
				clone,
				filepath.Join(clone, ".git"),
				filepath.Join(clone, ".git", "hooks"),
				filepath.Join(clone, ".git", "objects"),
				filepath.Join(clone, "plugins", "sample"),
			} {
				if !w.inClaudePluginStaging(path, 0) || !w.inClaudePluginStaging(path, claudeStagingGrace) {
					t.Errorf("%s is not left alone", path)
				}
			}
			if w.inClaudePluginStaging(real, 0) || w.inClaudePluginStaging(filepath.Join(cache, "mkt"), 0) {
				t.Error("a real plugin or its marketplace folder is left alone")
			}

			// A cache that already holds a clone when the watcher (re)starts
			// queues the real plugin and nothing of the clone.
			w.queueExistingClaudePlugins(context.Background(), cache, 0)
			for path := range w.pending {
				if strings.Contains(path, "temp_subdir_") || strings.Contains(filepath.ToSlash(path), "/.git") {
					t.Errorf("queued %s", path)
				}
			}
			if _, ok := w.pending[real]; !ok {
				t.Errorf("real plugin %s not queued: %v", real, w.pending)
			}
		})
	}
}

// The Secure Client profile keeps the watcher it had.
func TestClaudePluginUpdateCloneSecureClientUnchanged(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Guardrail.Connector = "claudecode"
	cfg.DeploymentMode = "managed_enterprise"
	cfg.Enterprise.Profile = "secure_client"
	cache := filepath.Join(t.TempDir(), ".claude", "plugins", "cache")
	clone := cloneStagingTree(t, cache, "temp_subdir_1_ab.clone")
	w := New(cfg, nil, []string{cache}, store, logger, nil, nil)
	if w.inClaudePluginStaging(filepath.Join(clone, ".git", "hooks"), 0) {
		t.Fatal("secure client profile changed")
	}
}

// Live: the staging clone appears and fills while the watcher runs, as it does
// during "claude plugin update". No folder of it reaches admission or is
// quarantined; a plugin the agent really loads still does.
func TestLiveWatcherLeavesClaudePluginUpdateCloneAlone(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Guardrail.Connector = "claudecode"
	cache := filepath.Join(t.TempDir(), ".claude", "plugins", "cache")
	if err := os.MkdirAll(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	seen := map[string]string{}
	w := New(cfg, nil, []string{cache}, store, logger, nil, func(r AdmissionResult) {
		mu.Lock()
		seen[r.Event.Name] = r.Event.Path
		mu.Unlock()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- w.Run(ctx) }()
	time.Sleep(500 * time.Millisecond)

	clone := filepath.Join(cache, "temp_subdir_1793946491108_t2ymk0.clone")
	for _, dir := range []string{"info", "hooks", "objects", "refs", "logs"} {
		if err := os.MkdirAll(filepath.Join(clone, ".git", dir), 0o700); err != nil {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	// The plugin the update installs, after the clone.
	version := filepath.Join(cache, "mkt", "sample", "1.0.1")
	if err := os.MkdirAll(filepath.Join(version, ".claude-plugin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(version, ".claude-plugin", "plugin.json"), []byte(`{"name":"sample"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(8 * time.Second)
	for done := false; !done; {
		mu.Lock()
		_, ok := seen["sample@mkt"]
		mu.Unlock()
		if ok {
			break
		}
		select {
		case <-deadline:
			done = true
		case <-time.After(50 * time.Millisecond):
		}
	}
	// Let anything queued for the clone settle before judging.
	time.Sleep(2 * time.Second)
	cancel()
	<-errCh

	mu.Lock()
	defer mu.Unlock()
	if _, ok := seen["sample@mkt"]; !ok {
		t.Fatalf("the real plugin was not admitted: %v", seen)
	}
	var names []string
	for name := range seen {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		if strings.Contains(name, "temp_subdir_") || strings.HasPrefix(name, ".git@") {
			t.Fatalf("clone folder admitted as a plugin: %v", names)
		}
	}
	// Nothing was moved out of the clone.
	if _, err := os.Stat(filepath.Join(clone, ".git", "objects")); err != nil {
		t.Fatalf("clone .git/objects was taken away: %v", err)
	}
}
