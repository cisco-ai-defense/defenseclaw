// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// A Claude Code plugin tree that lands in the cache in one go (a copy, an
// extracted archive) has its <marketplace>/<plugin>/<version> folder in place
// before the watch on its parent exists. The live watcher used to see only the
// marketplace folder's create event, so the plugin got no admission verdict
// until the hourly rescan, which only baselines it.
func TestLiveWatcherAdmitsClaudePluginTreeCreatedAtOnce(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Guardrail.Connector = "claudecode"
	seen := liveWatchClaudePluginTree(t, cfg, store, logger, 8*time.Second, true)
	if got := seen["defenseclaw@wecv-mkt"]; got == "" {
		t.Fatalf("admissions = %v, want defenseclaw@wecv-mkt", seen)
	}
}

// The Secure Client deployment keeps the watcher it had: the queueing of
// folders that already exist below a new cache folder does not run there.
func TestQueueExistingClaudePluginsSkipsSecureClient(t *testing.T) {
	for _, tc := range []struct {
		name         string
		secureClient bool
		want         int
	}{{"standalone or per-user", false, 1}, {"Secure Client", true, 0}} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, store, logger, _ := setupTestEnv(t)
			cfg.Guardrail.Connector = "claudecode"
			if tc.secureClient {
				cfg.DeploymentMode = "managed_enterprise"
				cfg.Enterprise.Profile = "secure_client"
			}
			cache := filepath.Join(t.TempDir(), ".claude", "plugins", "cache")
			marketplace := filepath.Join(cache, "mkt")
			if err := os.MkdirAll(filepath.Join(marketplace, "plug", "1.0.0"), 0o700); err != nil {
				t.Fatal(err)
			}
			w := New(cfg, nil, []string{cache}, store, logger, nil, nil)
			w.queueExistingClaudePlugins(context.Background(), marketplace, 1)
			if got := len(w.pending); got != tc.want {
				t.Fatalf("queued %d folders, want %d", got, tc.want)
			}
		})
	}
}

func liveWatchClaudePluginTree(t *testing.T, cfg *config.Config, store *audit.Store, logger *audit.Logger, wait time.Duration, mustSee bool) map[string]string {
	t.Helper()
	cache := filepath.Join(t.TempDir(), ".claude", "plugins", "cache")
	if err := os.MkdirAll(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg.AssetPolicy.Plugin.Allowed = append(cfg.AssetPolicy.Plugin.Allowed,
		config.AssetPolicyRule{Name: "defenseclaw@wecv-mkt", Reason: "pre-approved"})

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

	version := filepath.Join(cache, "wecv-mkt", "defenseclaw", "1.0.1")
	if err := os.MkdirAll(filepath.Join(version, ".claude-plugin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(version, ".claude-plugin", "plugin.json"), []byte(`{"name":"defenseclaw"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	deadline := time.After(wait)
	for done := false; !done; {
		mu.Lock()
		got, ok := seen["defenseclaw@wecv-mkt"]
		mu.Unlock()
		if ok && mustSee {
			if got != version {
				t.Fatalf("admitted path = %q, want %q", got, version)
			}
			break
		}
		select {
		case <-deadline:
			done = true
		case <-time.After(50 * time.Millisecond):
		}
	}
	cancel()
	<-errCh
	mu.Lock()
	defer mu.Unlock()
	out := map[string]string{}
	for k, v := range seen {
		out[k] = v
	}
	return out
}

// GAP-0629: Claude Code builds a plugin in cache/temp_local_<id> and then
// moves it to <marketplace>/<plugin>/<version>; the watcher scanned the
// staging copy as a plugin and held it while the move ran, so a clean
// plugin failed to install. Staging is left alone; the final folder is
// still a plugin.
func TestClaudePluginStagingIsNotAPlugin(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Guardrail.Connector = "claudecode"
	cache := filepath.Join(t.TempDir(), ".claude", "plugins", "cache")
	staging := filepath.Join(cache, "temp_local_1759900000000", "skills", "epa-plug-ok-skill")
	final := filepath.Join(cache, "epa-market", "epa-plug-ok", "1.0.0")
	marketplace := filepath.Join(cache, "temp_review", "sample-plugin", "1.0.0")
	for _, dir := range []string{staging, final, marketplace} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	w := New(cfg, nil, []string{cache}, store, logger, nil, nil)
	if !w.inClaudePluginStaging(staging, 0) || w.inClaudePluginStaging(final, 0) ||
		w.inClaudePluginStaging(marketplace, 0) {
		t.Fatal("staging and final folders are not told apart")
	}
	var plugins []string
	for _, evt := range w.enumerateTargets() {
		plugins = append(plugins, evt.Path)
	}
	if len(plugins) != 2 || !slices.Contains(plugins, final) || !slices.Contains(plugins, marketplace) {
		t.Fatalf("rescan targets %v, want %s and %s", plugins, final, marketplace)
	}
}

// #1428: Claude Code's "plugin update" clones into
// cache/temp_subdir_<n>_<rand>.clone/ and fills .git/{objects,hooks,...}.
// Those look like <marketplace>/<plugin>/<version> and were quarantined as
// .git@temp_subdir_*.clone (MANIFEST-MISSING), so every update failed.
// Staging clones are left alone; .git internals are never plugins; a real
// marketplace version folder is still a plugin.
func TestClaudePluginUpdateStagingCloneIsNotAPlugin(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Guardrail.Connector = "claudecode"
	cache := filepath.Join(t.TempDir(), ".claude", "plugins", "cache")
	staging := filepath.Join(cache, "temp_subdir_1793946491108_t2ymk0.clone")
	gitHooks := filepath.Join(staging, ".git", "hooks")
	gitObjects := filepath.Join(staging, ".git", "objects")
	stagingSkill := filepath.Join(staging, "skills", "example")
	final := filepath.Join(cache, "epa-market", "epa-plug-ok", "1.0.0")
	for _, dir := range []string{gitHooks, gitObjects, stagingSkill, final} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	w := New(cfg, nil, []string{cache}, store, logger, nil, nil)

	if !isPluginStagingFolder(filepath.Base(staging)) {
		t.Fatal("temp_subdir_*.clone is not a staging folder")
	}
	if isPluginStagingFolder("epa-market") || isPluginStagingFolder("temp_subdir") ||
		isPluginStagingFolder("temp_subdir_tools") {
		t.Fatal("marketplace names must not look like staging")
	}
	if !isPluginStagingFolder("temp_subdir_1793946491108_t2ymk0.clone") {
		t.Fatal("temp_subdir_*.clone must be staging")
	}
	for _, path := range []string{staging, gitHooks, gitObjects} {
		if !w.inClaudePluginStaging(path, 0) {
			t.Fatalf("%s is not under staging", path)
		}
	}
	if w.inClaudePluginStaging(final, 0) {
		t.Fatal("final version folder must not be staging")
	}
	if id, ok := w.claudePluginIdentity(gitHooks); ok {
		t.Fatalf("claudePluginIdentity(.git/hooks) = %q, want not a plugin", id)
	}
	if id, ok := w.claudePluginIdentity(final); !ok || id != "epa-plug-ok@epa-market" {
		t.Fatalf("claudePluginIdentity(final) = %q ok=%v", id, ok)
	}

	var plugins []string
	for _, evt := range w.enumerateTargets() {
		plugins = append(plugins, evt.Path)
	}
	if len(plugins) != 1 || plugins[0] != final {
		t.Fatalf("rescan targets %v, want only %s", plugins, final)
	}

	w.queueExistingClaudePlugins(context.Background(), cache, 0)
	if len(w.pending) != 1 {
		t.Fatalf("queued %d folders, want 1 (final only): %v", len(w.pending), w.pending)
	}
	if _, ok := w.pending[final]; !ok {
		t.Fatalf("queued %v, want %s", w.pending, final)
	}
}

func TestPathHasGitDirSegment(t *testing.T) {
	for _, tc := range []struct {
		path string
		want bool
	}{
		{filepath.Join("cache", "temp_subdir_1.clone", ".git", "hooks"), true},
		{filepath.Join("cache", "mkt", "plug", "1.0.0"), false},
		{filepath.Join("cache", "mkt", "plug", "1.0.0", "README.md"), false},
		{".git", true},
	} {
		if got := pathHasGitDirSegment(tc.path); got != tc.want {
			t.Errorf("pathHasGitDirSegment(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}
