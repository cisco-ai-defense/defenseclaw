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

func TestIsClaudePluginUpdateClone(t *testing.T) {
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"temp_subdir_1793946491108_t2ymk0.clone", true},
		{"temp_subdir_1793946489634_kkth3d.clone", true},
		{"TEMP_SUBDIR_1_ABC.clone", true},
		{"temp_subdir_tools.clone", false},
		{"temp_subdir_1.clone", false},
		{"temp_subdir__abc.clone", false},
		{"temp_subdir_1_.clone", false},
		{"temp_subdir_x1_abc.clone", false},
		{"temp_subdir_1_ab-c.clone", false},
		{"temp_subdir_1_abc_def.clone", false},
		{"temp_subdir_1_abc", false},
	} {
		if got := isClaudePluginUpdateClone(tc.name); got != tc.want {
			t.Errorf("isClaudePluginUpdateClone(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestIsClaudePluginGitClone(t *testing.T) {
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"temp_git_1775652472167_8bp378", true},
		{"TEMP_GIT_1_ABC", true},
		{"temp_git_tools", false},
		{"temp_git_1", false},
		{"temp_git__abc", false},
		{"temp_git_1_", false},
		{"temp_git_x1_abc", false},
		{"temp_git_1_ab-c", false},
		{"temp_git_1_abc.clone", false},
		{"temp_git_1_abc_def", false},
	} {
		if got := isClaudePluginGitClone(tc.name); got != tc.want {
			t.Errorf("isClaudePluginGitClone(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// CodeRabbit on #1432: installing from a Git URL clones the source into
// cache/temp_git_<n>_<rand> first. While Claude Code is still copying from
// it, the clone is staging: live events skip it and the rescan leaves it
// alone. A leftover clone older than the grace is scanned again, and a
// marketplace named temp_git_tools is never staging.
func TestClaudePluginGitCloneIsStagingOnlyDuringGrace(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Guardrail.Connector = "claudecode"
	cache := filepath.Join(t.TempDir(), ".claude", "plugins", "cache")
	clone := filepath.Join(cache, "temp_git_1775652472167_8bp378")
	cloneSkill := filepath.Join(clone, "skills", "brainstorming")
	marketplace := filepath.Join(cache, "temp_git_tools", "tool-plug", "1.0.0")
	final := filepath.Join(cache, "epa-market", "epa-plug-ok", "1.0.0")
	for _, dir := range []string{cloneSkill, marketplace, final} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	w := New(cfg, nil, []string{cache}, store, logger, nil, nil)

	if !w.inClaudePluginStaging(cloneSkill, 0) || !w.inClaudePluginStaging(cloneSkill, claudeStagingGrace) {
		t.Fatal("a fresh temp_git clone must be staging")
	}
	if w.inClaudePluginStaging(marketplace, 0) || w.inClaudePluginStaging(final, 0) {
		t.Fatal("marketplace and final version folders must not be staging")
	}
	targets := func() []string {
		var plugins []string
		for _, evt := range w.enumerateTargets() {
			plugins = append(plugins, evt.Path)
		}
		return plugins
	}
	if got := targets(); len(got) != 2 || !slices.Contains(got, marketplace) || !slices.Contains(got, final) {
		t.Fatalf("rescan targets %v, want %s and %s", got, marketplace, final)
	}

	old := time.Now().Add(-2 * claudeStagingGrace)
	if err := os.Chtimes(clone, old, old); err != nil {
		t.Fatal(err)
	}
	if w.inClaudePluginStaging(cloneSkill, claudeStagingGrace) {
		t.Fatal("a temp_git clone older than the grace must be scanned again")
	}
	if got := targets(); !slices.Contains(got, cloneSkill) {
		t.Fatalf("rescan targets %v, want the leftover clone %s", got, cloneSkill)
	}
}

// CodeRabbit on #1432: marketplace names may use ".", "_" and "-", so a
// registered marketplace named temp_subdir_tools.clone is valid. Its plugin
// versions must still be admitted by live events, rescans and the startup walk.
func TestClaudeMarketplaceNamedLikeUpdateCloneIsStillScanned(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Guardrail.Connector = "claudecode"
	cache := filepath.Join(t.TempDir(), ".claude", "plugins", "cache")
	marketplace := filepath.Join(cache, "temp_subdir_tools.clone")
	version := filepath.Join(marketplace, "tool-plug", "1.0.0")
	if err := os.MkdirAll(version, 0o700); err != nil {
		t.Fatal(err)
	}
	w := New(cfg, nil, []string{cache}, store, logger, nil, nil)

	if w.inClaudePluginStaging(version, 0) || w.inClaudePluginStaging(version, claudeStagingGrace) {
		t.Fatal("plugin version in a registered marketplace must not be staging")
	}
	if id, ok := w.claudePluginIdentity(version); !ok || id != "tool-plug@temp_subdir_tools.clone" {
		t.Fatalf("claudePluginIdentity(version) = %q ok=%v", id, ok)
	}
	var plugins []string
	for _, evt := range w.enumerateTargets() {
		plugins = append(plugins, evt.Path)
	}
	if len(plugins) != 1 || plugins[0] != version {
		t.Fatalf("rescan targets %v, want only %s", plugins, version)
	}
	w.queueExistingClaudePlugins(context.Background(), cache, 0)
	if _, ok := w.pending[version]; !ok || len(w.pending) != 1 {
		t.Fatalf("queued %v, want only %s", w.pending, version)
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

// CodeRabbit on #1432: if Run hands queueExistingClaudePlugins a populated
// .git directory (marketplace is not a plugin copy), walking it would queue
// non-dot children such as "objects". Bail when dir itself is under .git.
func TestQueueExistingClaudePluginsSkipsGitDirRoot(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Guardrail.Connector = "claudecode"
	cache := filepath.Join(t.TempDir(), ".claude", "plugins", "cache")
	gitDir := filepath.Join(cache, "marketplace", ".git")
	objects := filepath.Join(gitDir, "objects")
	if err := os.MkdirAll(objects, 0o700); err != nil {
		t.Fatal(err)
	}
	w := New(cfg, nil, []string{cache}, store, logger, nil, nil)
	w.queueExistingClaudePlugins(context.Background(), gitDir, 2)
	if len(w.pending) != 0 {
		t.Fatalf("queued %v from .git root, want none", w.pending)
	}
}

// Each exclusion in queueDueIssues is checked on its own (a .git path inside a
// staging clone would match both), and a cache that itself sits below a folder
// named .git still has its plugin issues retried.
func TestQueueDueIssuesClearsStagingAndGitIssues(t *testing.T) {
	tests := []struct {
		name string
		// cacheParent is joined below the temp dir; the cache root is
		// <cacheParent>/.claude/plugins/cache.
		cacheParent string
		// path is the issue path below the cache root.
		path      []string
		wantRetry bool
	}{
		{name: "staging clone", path: []string{"temp_subdir_1_abc.clone", "hooks"}},
		{name: "git internals", path: []string{"marketplace", "plugin", ".git", "hooks"}},
		{name: "plugin version", path: []string{"marketplace", "plugin", "1.0.0"}, wantRetry: true},
		{
			name:      "plugin version in a marketplace named like a clone",
			path:      []string{"temp_subdir_tools.clone", "plugin", "1.0.0"},
			wantRetry: true,
		},
		{
			name:        "plugin version in a cache below .git",
			cacheParent: filepath.Join("dotfiles", ".git", "home"),
			path:        []string{"marketplace", "plugin", "1.0.0"},
			wantRetry:   true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, store, logger, _ := setupTestEnv(t)
			cfg.Guardrail.Connector = "claudecode"
			cache := filepath.Join(t.TempDir(), tc.cacheParent, ".claude", "plugins", "cache")
			issuePath := filepath.Join(append([]string{cache}, tc.path...)...)
			if err := os.MkdirAll(issuePath, 0o700); err != nil {
				t.Fatal(err)
			}
			w := New(cfg, nil, []string{cache}, store, logger, nil, nil)
			w.state.setIssue(AdmissionIssue{
				Type: string(InstallPlugin),
				Name: filepath.Base(issuePath),
				Path: issuePath,
				Kind: AdmissionUnscanned,
			})
			// Force the retry due so queueDueIssues sees it immediately.
			w.state.mu.Lock()
			r := w.state.retry[issuePath]
			r.due = w.state.now().Add(-time.Second)
			w.state.retry[issuePath] = r
			w.state.mu.Unlock()
			// dueIssues pushes the retry time forward, so do not call it
			// here: queueDueIssues would then find nothing due and the test
			// would pass without reaching the exclusions.
			w.queueDueIssues()
			_, queued := w.pending[issuePath]
			if queued != tc.wantRetry {
				t.Fatalf("queued = %v, want %v (pending %v)", queued, tc.wantRetry, w.pending)
			}
			w.state.mu.Lock()
			_, recorded := w.state.issues[issuePath]
			w.state.mu.Unlock()
			if recorded == !tc.wantRetry {
				t.Fatalf("issue still recorded = %v, want %v", recorded, tc.wantRetry)
			}
		})
	}
}

// CodeRabbit on #1432: the .git check in queueExistingClaudePlugins must only
// look below the cache root. A cache whose own path has a .git ancestor still
// has its installed plugin versions queued.
func TestQueueExistingClaudePluginsCacheBelowGitAncestor(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Guardrail.Connector = "claudecode"
	cache := filepath.Join(t.TempDir(), "dotfiles", ".git", "home", ".claude", "plugins", "cache")
	marketplace := filepath.Join(cache, "marketplace")
	version := filepath.Join(marketplace, "plugin", "1.0.0")
	if err := os.MkdirAll(version, 0o700); err != nil {
		t.Fatal(err)
	}
	w := New(cfg, nil, []string{cache}, store, logger, nil, nil)
	w.queueExistingClaudePlugins(context.Background(), marketplace, 1)
	if _, ok := w.pending[version]; !ok {
		t.Fatalf("pending %v, want %s queued", w.pending, version)
	}
}

func TestInClaudeCacheGitDir(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Guardrail.Connector = "claudecode"
	base := t.TempDir()
	cache := filepath.Join(base, "repo", ".git", "plugins", "cache")
	w := New(cfg, nil, []string{cache}, store, logger, nil, nil)
	tests := []struct {
		path string
		want bool
	}{
		{filepath.Join(cache, "marketplace", "plugin", ".git", "objects"), true},
		{filepath.Join(cache, "marketplace", ".GIT"), true},
		{filepath.Join(cache, "marketplace", "plugin", "1.0.0"), false},
		{cache, false},
		{filepath.Join(base, "repo", ".git", "hooks"), false},
	}
	for _, tc := range tests {
		if got := w.inClaudeCacheGitDir(tc.path); got != tc.want {
			t.Errorf("inClaudeCacheGitDir(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}
