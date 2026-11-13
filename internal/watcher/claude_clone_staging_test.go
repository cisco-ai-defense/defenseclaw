// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// Issue #1428: "claude plugin update" clones the marketplace into
// <cache>/temp_subdir_<ts>_<random>.clone. The watcher read each folder of its
// .git (hooks, objects, refs, info, logs) as a <marketplace>/<plugin>/<version>
// plugin named ".git@temp_subdir_<ts>.clone", found no manifest and
// quarantined the git object store, so the update failed. The other staging
// folders (temp_github_<ts>_<r>/skills/foo read as "skills@temp_github_...")
// and <version>.linking-<pid> had the same problem. A marketplace named like
// a near miss (".git", "temp_subdir_a.clone") is still scanned.

// stagingName is a Claude Code staging folder name stamped at.
func stagingName(kind, suffix string, at time.Time) string {
	return fmt.Sprintf("temp_%s_%d_t2ymk0%s", kind, at.UnixMilli(), suffix)
}

func mkdirs(t *testing.T, dirs ...string) {
	t.Helper()
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
}

func writeManifest(t *testing.T, dir, name string) {
	t.Helper()
	mkdirs(t, filepath.Join(dir, ".claude-plugin"))
	if err := os.WriteFile(filepath.Join(dir, ".claude-plugin", "plugin.json"), []byte(`{"name":"`+name+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
}

// cloneStagingTree builds a staging clone like Claude Code's, with a plugin
// folder of the marketplace inside it, and returns its path.
func cloneStagingTree(t *testing.T, cache, name string) string {
	t.Helper()
	clone := filepath.Join(cache, name)
	for _, dir := range []string{"hooks", "objects", "refs", "info", "logs"} {
		mkdirs(t, filepath.Join(clone, ".git", dir))
	}
	writeManifest(t, filepath.Join(clone, "plugins", "sample"), "sample")
	return clone
}

// githubStagingTree builds the folder a github-source plugin is cloned into:
// the repository with its skills and its .git, so skills/foo sits where a
// <marketplace>/<plugin>/<version> folder would.
func githubStagingTree(t *testing.T, cache, name string) string {
	t.Helper()
	staging := filepath.Join(cache, name)
	mkdirs(t, filepath.Join(staging, ".git", "objects"), filepath.Join(staging, "skills", "foo"))
	if err := os.WriteFile(filepath.Join(staging, "skills", "foo", "SKILL.md"), []byte("# foo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return staging
}

func pluginTargets(w *InstallWatcher) []string {
	var out []string
	for _, evt := range w.enumerateTargets() {
		if evt.Type == InstallPlugin {
			out = append(out, evt.Path)
		}
	}
	slices.Sort(out)
	return out
}

func pendingPaths(w *InstallWatcher) []string {
	var out []string
	for path := range w.pending {
		out = append(out, path)
	}
	slices.Sort(out)
	return out
}

func sorted(paths ...string) []string {
	out := slices.Clone(paths)
	slices.Sort(out)
	return out
}

// claudeCacheFixture is a Claude Code cache with fresh installs in flight
// and plugins (some with near-miss names) the agent loads.
type claudeCacheFixture struct {
	cache, clone, github, linking string
	plugins                       []string
}

func newClaudeCacheFixture(t *testing.T, at time.Time) claudeCacheFixture {
	t.Helper()
	cache := filepath.Join(t.TempDir(), ".claude", "plugins", "cache")
	f := claudeCacheFixture{
		cache:   cache,
		clone:   cloneStagingTree(t, cache, stagingName("subdir", ".clone", at)),
		github:  githubStagingTree(t, cache, stagingName("github", "", at)),
		linking: filepath.Join(cache, "mkt", "sample", "1.0.1.linking-4242"),
	}
	writeManifest(t, f.linking, "sample")
	real := filepath.Join(cache, "mkt", "real", "1.0.0")
	mkdirs(t, filepath.Join(real, ".git", "objects"))
	gitMarket := filepath.Join(cache, ".git", "evil", "1.0.0")
	writeManifest(t, gitMarket, "evil")
	cloneMarket := filepath.Join(cache, "temp_subdir_a.clone", "evil", "1.0.0")
	writeManifest(t, cloneMarket, "evil")
	gitPlugin := filepath.Join(cache, "mkt", ".git", "hooks")
	mkdirs(t, gitPlugin)
	upper := filepath.Join(cache, strings.ToUpper(stagingName("local", "", at)), "evil", "1.0.0")
	writeManifest(t, upper, "evil")
	f.plugins = sorted(real, gitMarket, cloneMarket, gitPlugin, upper)
	return f
}

func claudeWatcher(t *testing.T, cache string) *InstallWatcher {
	t.Helper()
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Guardrail.Connector = "claudecode"
	return New(cfg, nil, []string{cache}, store, logger, nil, nil)
}

func TestClaudePluginInstallsInFlightAreNotPlugins(t *testing.T) {
	f := newClaudeCacheFixture(t, time.Now())
	w := claudeWatcher(t, f.cache)

	if got := pluginTargets(w); !slices.Equal(got, f.plugins) {
		t.Fatalf("rescan targets\n%v\nwant\n%v", got, f.plugins)
	}
	// The live watcher reads the same folders as it is told of them.
	for _, path := range []string{
		f.clone,
		filepath.Join(f.clone, ".git"),
		filepath.Join(f.clone, ".git", "hooks"),
		filepath.Join(f.clone, ".git", "objects"),
		filepath.Join(f.clone, "plugins", "sample"),
		f.github,
		filepath.Join(f.github, "skills"),
		filepath.Join(f.github, "skills", "foo"),
		filepath.Join(f.github, ".git", "objects"),
		f.linking,
	} {
		if !w.inClaudePluginStaging(path, 0) || !w.inClaudePluginStaging(path, claudeStagingGrace) {
			t.Errorf("%s is not left alone", path)
		}
	}
	for _, path := range append(slices.Clone(f.plugins), filepath.Join(f.cache, "mkt"), filepath.Join(f.cache, ".git")) {
		if w.inClaudePluginStaging(path, 0) {
			t.Errorf("plugin or marketplace %s is left alone", path)
		}
	}
	// A cache that already holds them when the watcher (re)starts queues the
	// plugins and nothing in flight.
	w.queueExistingClaudePlugins(context.Background(), f.cache, 0)
	if got := pendingPaths(w); !slices.Equal(got, f.plugins) {
		t.Fatalf("queued\n%v\nwant\n%v", got, f.plugins)
	}
}

// A staging or linking folder still there after the window is scanned, git's
// files in a staging clone included, so a folder named like one is no scan
// hole.
func TestClaudePluginStaleStagingIsScanned(t *testing.T) {
	f := newClaudeCacheFixture(t, time.Now())
	w := claudeWatcher(t, f.cache)
	w.stagingClock = func() time.Time { return time.Now().Add(2 * time.Hour) }

	want := slices.Clone(f.plugins)
	for _, dir := range []string{"hooks", "objects", "refs", "info", "logs"} {
		want = append(want, filepath.Join(f.clone, ".git", dir))
	}
	want = sorted(append(want,
		filepath.Join(f.clone, "plugins", "sample"),
		filepath.Join(f.github, ".git", "objects"),
		filepath.Join(f.github, "skills", "foo"),
		f.linking)...)
	if got := pluginTargets(w); !slices.Equal(got, want) {
		t.Fatalf("rescan targets\n%v\nwant\n%v", got, want)
	}
	for _, path := range []string{filepath.Join(f.github, "skills"), filepath.Join(f.clone, ".git", "hooks"), f.linking} {
		if w.inClaudePluginStaging(path, 0) {
			t.Errorf("stale %s is left alone", path)
		}
	}
}

// A marketplace Claude Code registered under a staging-like name is a
// marketplace, and a folder holding a registered install path (a linking
// folder, a clone with its .git) is plugins.
func TestClaudePluginRegisteredStagingNameIsAPlugin(t *testing.T) {
	f := newClaudeCacheFixture(t, time.Now())
	plugins := filepath.Dir(f.cache)
	github := filepath.Base(f.github)
	if err := os.WriteFile(filepath.Join(plugins, "known_marketplaces.json"),
		[]byte(`{"`+github+`":{"source":{"source":"github","repo":"o/r"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	installed := fmt.Sprintf(`{"version":2,"plugins":{"sample@mkt":[{"scope":"user","installPath":%q}],`+
		`"sample@other":[{"scope":"user","installPath":%q}]}}`, f.linking, filepath.Join(f.clone, "plugins", "sample"))
	if err := os.WriteFile(filepath.Join(plugins, "installed_plugins.json"), []byte(installed), 0o600); err != nil {
		t.Fatal(err)
	}
	w := claudeWatcher(t, f.cache)
	want := slices.Clone(f.plugins)
	for _, dir := range []string{"hooks", "objects", "refs", "info", "logs"} {
		want = append(want, filepath.Join(f.clone, ".git", dir))
	}
	want = sorted(append(want,
		filepath.Join(f.clone, "plugins", "sample"),
		filepath.Join(f.github, "skills", "foo"),
		filepath.Join(f.github, ".git", "objects"),
		f.linking)...)
	if got := pluginTargets(w); !slices.Equal(got, want) {
		t.Fatalf("rescan targets\n%v\nwant\n%v", got, want)
	}
	if w.inClaudePluginStaging(filepath.Join(f.github, "skills", "foo"), 0) ||
		w.inClaudePluginStaging(f.linking, 0) ||
		w.inClaudePluginStaging(filepath.Join(f.clone, ".git", "hooks"), 0) {
		t.Error("a registered marketplace or install path is left alone")
	}
}

// Codex keeps its cache as it was: Claude Code's staging names are folders
// like any other there; DefenseClaw's own .dclaw-stage- copy is still left
// alone.
func TestCodexPluginCacheIgnoresClaudeStagingNames(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Guardrail.Connector = "codex"
	cache := filepath.Join(t.TempDir(), ".codex", "plugins", "cache")
	staging := filepath.Join(cache, stagingName("local", "", time.Now()), "skills", "x")
	own := filepath.Join(cache, ".dclaw-stage-x-ab12", "p", "1.0.0")
	mkdirs(t, staging, own)
	w := New(cfg, nil, []string{cache}, store, logger, nil, nil)
	if w.inClaudePluginStaging(staging, 0) || !w.inClaudePluginStaging(own, 0) {
		t.Fatal("codex cache staging rules changed")
	}
	if got := pluginTargets(w); !slices.Equal(got, []string{staging}) {
		t.Fatalf("rescan targets %v, want %s", got, staging)
	}
}

// The Secure Client profile keeps the watcher it had.
func TestClaudePluginUpdateCloneSecureClientUnchanged(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Guardrail.Connector = "claudecode"
	cfg.DeploymentMode = "managed_enterprise"
	cfg.Enterprise.Profile = "secure_client"
	cache := filepath.Join(t.TempDir(), ".claude", "plugins", "cache")
	clone := cloneStagingTree(t, cache, stagingName("subdir", ".clone", time.Now()))
	linking := filepath.Join(cache, "mkt", "sample", "1.0.1.linking-4242")
	mkdirs(t, linking)
	w := New(cfg, nil, []string{cache}, store, logger, nil, nil)
	if w.inClaudePluginStaging(filepath.Join(clone, ".git", "hooks"), 0) ||
		w.inClaudePluginStaging(filepath.Join(clone, "plugins", "sample"), 0) ||
		w.inClaudePluginStaging(linking, 0) {
		t.Fatal("secure client profile changed")
	}
}

// Live: a staging clone, a github staging tree and a linking folder appear
// and fill while the watcher runs, as they do during "claude plugin
// install/update". None of them reaches admission or is quarantined; the
// plugin the linking folder becomes, and plugins of marketplaces named
// ".git" and "temp_subdir_a.clone", are admitted.
func TestLiveWatcherLeavesClaudePluginUpdateCloneAlone(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Guardrail.Connector = "claudecode"
	cache := filepath.Join(t.TempDir(), ".claude", "plugins", "cache")
	mkdirs(t, filepath.Join(cache, "mkt", "sample"))
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

	clone := filepath.Join(cache, stagingName("subdir", ".clone", time.Now()))
	for _, dir := range []string{"info", "hooks", "objects", "refs", "logs"} {
		mkdirs(t, filepath.Join(clone, ".git", dir))
		time.Sleep(50 * time.Millisecond)
	}
	writeManifest(t, filepath.Join(clone, "plugins", "sample"), "sample")
	github := githubStagingTree(t, cache, stagingName("github", "", time.Now()))
	linking := filepath.Join(cache, "mkt", "sample", "1.0.1.linking-4242")
	writeManifest(t, linking, "sample")
	time.Sleep(300 * time.Millisecond)
	// Claude Code renames the linked folder to the version it installs.
	if err := os.Rename(linking, filepath.Join(cache, "mkt", "sample", "1.0.1")); err != nil {
		t.Fatal(err)
	}
	writeManifest(t, filepath.Join(cache, ".git", "evil", "1.0.0"), "evil")
	writeManifest(t, filepath.Join(cache, "temp_subdir_a.clone", "evil", "1.0.0"), "evil")

	want := []string{"sample@mkt", "evil@.git", "evil@temp_subdir_a.clone"}
	deadline := time.After(10 * time.Second)
	for done := false; !done; {
		mu.Lock()
		all := true
		for _, name := range want {
			if _, ok := seen[name]; !ok {
				all = false
			}
		}
		mu.Unlock()
		if all {
			break
		}
		select {
		case <-deadline:
			done = true
		case <-time.After(50 * time.Millisecond):
		}
	}
	// Let anything queued for the staging folders settle before judging.
	time.Sleep(2 * time.Second)
	cancel()
	<-errCh

	mu.Lock()
	defer mu.Unlock()
	var names []string
	for name := range seen {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range want {
		if _, ok := seen[name]; !ok {
			t.Errorf("plugin %s was not admitted: %v", name, names)
		}
	}
	for _, name := range names {
		if strings.Contains(name, filepath.Base(clone)) || strings.Contains(name, filepath.Base(github)) ||
			strings.Contains(name, ".linking-") || strings.HasPrefix(name, ".git@") {
			t.Errorf("install in flight admitted as a plugin: %v", names)
		}
	}
	// Nothing was moved out of the staging folders.
	for _, path := range []string{filepath.Join(clone, ".git", "objects"), filepath.Join(github, "skills", "foo")} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("%s was taken away: %v", path, err)
		}
	}
}

// A real plugin whose version ends in .linking-<n> (1.0.0-x.linking-1;
// Claude Code keeps a .linking-<pid> folder while its pid lives, pid 1
// always) is left alone only while it is written. Then the rescan admits it
// (scan, verdict, block/quarantine) like a new plugin; it used to record
// only a baseline, so nothing it held was enforced.
func TestClaudeLinkingVersionPluginIsAdmittedAfterGrace(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Guardrail.Connector = "claudecode"
	cache := filepath.Join(t.TempDir(), ".claude", "plugins", "cache")
	linked := filepath.Join(cache, "mkt", "pid1", "1.0.0-x.linking-1")
	plain := filepath.Join(cache, "mkt", "plain", "1.0.0")
	writeManifest(t, linked, "pid1")
	writeManifest(t, plain, "plain")
	var mu sync.Mutex
	admitted := map[string]int{}
	w := New(cfg, nil, []string{cache}, store, logger, nil, func(r AdmissionResult) {
		mu.Lock()
		admitted[r.Event.Path]++
		mu.Unlock()
	})
	clock := &stagingTestClock{}
	w.stagingClock = clock.now

	if got := pluginTargets(w); !slices.Equal(got, []string{plain}) {
		t.Fatalf("rescan targets while written %v, want %s", got, plain)
	}
	if _, ok := w.stagingDeferred[linked]; !ok {
		t.Fatalf("the rescan did not note %s for a re-check: %v", linked, w.stagingDeferred)
	}
	clock.advance(claudeStagingGrace + time.Minute)
	ctx := context.Background()
	for _, evt := range w.enumerateTargets() {
		if evt.Type == InstallPlugin {
			w.rescanTarget(ctx, evt, nil)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if admitted[linked] != 1 {
		t.Fatalf("the .linking- version plugin was admitted %d times, want 1: %v", admitted[linked], admitted)
	}
	if admitted[plain] != 0 {
		t.Fatalf("a plain plugin was admitted by a rescan without startup roots: %v", admitted)
	}
}

// The live watcher looks again at what it left alone: a path still there
// and settled is handed to admission, one gone is forgotten.
func TestRecheckClaudeStagingQueuesSettledPaths(t *testing.T) {
	f := newClaudeCacheFixture(t, time.Now())
	w := claudeWatcher(t, f.cache)
	clock := &stagingTestClock{}
	w.stagingClock = clock.now
	gone := filepath.Join(f.cache, "mkt", "gone", "1.0.0.linking-7")
	w.deferClaudeStaging(f.linking, 3)
	w.deferClaudeStaging(f.github, 1)
	w.deferClaudeStaging(gone, 3)
	got := map[string]int{}
	admit := func(path string, depth int) { got[path] = depth }

	w.recheckClaudeStaging(admit)
	if len(got) != 0 {
		t.Fatalf("installs in flight handed to admission: %v", got)
	}
	if _, ok := w.stagingDeferred[gone]; ok {
		t.Error("a path gone is still deferred")
	}
	clock.advance(claudeStagingGrace + time.Minute)
	w.recheckClaudeStaging(admit)
	if want := map[string]int{f.linking: 3, f.github: 1}; !maps.Equal(got, want) {
		t.Fatalf("handed to admission %v, want %v", got, want)
	}
	if len(w.stagingDeferred) != 0 {
		t.Fatalf("still deferred: %v", w.stagingDeferred)
	}

	// Admission takes them as new plugins.
	ctx := context.Background()
	w.admitClaudeStaging(ctx, f.linking, 3)
	w.admitClaudeStaging(ctx, f.github, 1)
	want := sorted(f.linking, filepath.Join(f.github, ".git", "objects"), filepath.Join(f.github, "skills", "foo"))
	if got := pendingPaths(w); !slices.Equal(got, want) {
		t.Fatalf("queued\n%v\nwant\n%v", got, want)
	}
}

// Live, with a test clock: a .linking- version plugin is left alone while
// written and admitted once settled; what is deferred when the watcher
// stops is dropped and never re-checked.
func TestLiveWatcherAdmitsLinkingVersionAfterGraceAndStopForgets(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Guardrail.Connector = "claudecode"
	cache := filepath.Join(t.TempDir(), ".claude", "plugins", "cache")
	mkdirs(t, filepath.Join(cache, "mkt", "pid1"))
	var mu sync.Mutex
	seen := map[string]bool{}
	w := New(cfg, nil, []string{cache}, store, logger, nil, func(r AdmissionResult) {
		mu.Lock()
		seen[r.Event.Name] = true
		mu.Unlock()
	})
	clock := &stagingTestClock{}
	w.stagingClock = clock.now
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- w.Run(ctx) }()
	time.Sleep(500 * time.Millisecond)

	deferred := func(path string) bool {
		w.stagingMu.Lock()
		defer w.stagingMu.Unlock()
		_, ok := w.stagingDeferred[path]
		return ok
	}
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		for deadline := time.Now().Add(10 * time.Second); !cond(); time.Sleep(50 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting: %s", what)
			}
		}
	}
	admitted := func() bool {
		mu.Lock()
		defer mu.Unlock()
		return seen["pid1@mkt"]
	}

	linked := filepath.Join(cache, "mkt", "pid1", "1.0.0-x.linking-1")
	writeManifest(t, linked, "pid1")
	waitFor("the linking folder deferred", func() bool { return deferred(linked) })
	time.Sleep(1500 * time.Millisecond)
	if admitted() {
		t.Fatal("a version folder being written was admitted")
	}
	clock.advance(claudeStagingGrace + time.Minute)
	waitFor("the settled .linking- version admitted", admitted)

	// Back to the real time, so the next folder is one being written.
	clock.offset.Store(0)
	other := filepath.Join(cache, "mkt", "pid1", "2.0.0.linking-9")
	writeManifest(t, other, "pid1")
	waitFor("the second linking folder deferred", func() bool { return deferred(other) })
	cancel()
	<-errCh
	w.stagingMu.Lock()
	left := len(w.stagingDeferred) + len(w.stagingSeen)
	w.stagingMu.Unlock()
	if left != 0 {
		t.Fatalf("deferred installs kept after stop: %d", left)
	}
	clock.advance(time.Hour)
	w.recheckClaudeStaging(func(path string, _ int) { t.Errorf("re-checked %s after stop", path) })
}
