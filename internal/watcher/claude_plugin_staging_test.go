// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// Issue #1428 review: the staging test is on the folder names relative to
// the cache, so it reads POSIX and Windows separators the same on every
// host. It is Claude Code's own pattern, exact and case-sensitive: a
// marketplace may be named ".git" or "temp_subdir_a.clone" and is still a
// marketplace.
func TestClassifyClaudeCacheParts(t *testing.T) {
	const ts = "1793946491108"
	for _, tc := range []struct {
		rel  string
		want claudeCacheEntry
	}{
		// Every staging kind, with and without its suffix.
		{`temp_subdir_` + ts + `_t2ymk0.clone`, claudeCacheStaging},
		{`temp_subdir_` + ts + `_t2ymk0.clone/plugins/sample`, claudeCacheStaging},
		{`temp_subdir_` + ts + `_t2ymk0.clone\plugins\sample`, claudeCacheStaging},
		{`temp_github_` + ts + `_ab12/skills/foo`, claudeCacheStaging},
		{`temp_github_` + ts + `_ab12\skills\foo`, claudeCacheStaging},
		{`temp_local_` + ts + `_k3x9q/skills/x`, claudeCacheStaging},
		{`temp_npm_` + ts + `_a/package/x`, claudeCacheStaging},
		{`temp_git_` + ts + `_zz_x/p/v`, claudeCacheStaging},
		{`temp_archive_` + ts + `_1/a/b`, claudeCacheStaging},
		{`temp_command_` + ts + `_q1w2e3/a/b`, claudeCacheStaging},
		{`temp_unknown_` + ts + `_x9/a/b`, claudeCacheStaging},
		// git's files in a staging clone are in it too.
		{`temp_subdir_` + ts + `_t2ymk0.clone/.git`, claudeCacheStaging},
		{`temp_subdir_` + ts + `_t2ymk0.clone/.git/hooks`, claudeCacheStaging},
		{`temp_subdir_` + ts + `_t2ymk0.clone\.git\objects`, claudeCacheStaging},
		{`temp_github_` + ts + `_ab12/.git/refs`, claudeCacheStaging},
		// A version folder being linked.
		{`mkt/plugin/1.0.0.linking-4242`, claudeCacheLinking},
		{`mkt\plugin\1.0.0.linking-4242\skills`, claudeCacheLinking},
		// Marketplace, plugin and version names Claude Code allows stay plugins.
		{`.git/plugin/1.0.0`, claudeCachePlugin},
		{`.git\plugin\1.0.0`, claudeCachePlugin},
		{`temp_subdir_a.clone/plugin/1.0.0`, claudeCachePlugin},
		{`temp_subdir_a.clone\plugin\1.0.0`, claudeCachePlugin},
		{`mkt/.git/hooks`, claudeCachePlugin},
		{`mkt/plugin/.git`, claudeCachePlugin},
		{`mkt/plugin/1.0.0/.git/objects`, claudeCachePlugin},
		{`mkt/plugin/1.0.0`, claudeCachePlugin},
		{`openai-curated-remote/github/1.2.0`, claudeCachePlugin},
		// Near misses of the staging pattern.
		{`TEMP_SUBDIR_` + ts + `_T2YMK0.CLONE/.git/hooks`, claudeCachePlugin},
		{`Temp_local_` + ts + `_abc/x/y`, claudeCachePlugin},
		{`temp_local_1759900000000/skills/x`, claudeCachePlugin},
		{`temp_local_123456789_abc/x/y`, claudeCachePlugin},
		{`temp_local_` + ts + `_abcdefg/x/y`, claudeCachePlugin},
		{`temp_local_` + ts + `_ABC/x/y`, claudeCachePlugin},
		{`temp_review_` + ts + `_abc/x/y`, claudeCachePlugin},
		{`temp_subdir_` + ts + `_t2ymk0.clone.bak/x/y`, claudeCachePlugin},
		{`temp_subdir_1_ab.clone/x/y`, claudeCachePlugin},
		{`mkt/temp_subdir_` + ts + `_t2ymk0.clone/1.0.0`, claudeCachePlugin},
		{`mkt/plugin/1.0.0.linking-`, claudeCachePlugin},
		{`mkt/plugin/1.0.0.linking-4x`, claudeCachePlugin},
		{`mkt/plugin/.linking-1`, claudeCachePlugin},
		{`mkt/plugin.linking-1/1.0.0`, claudeCachePlugin},
		{``, claudeCachePlugin},
	} {
		if got := classifyClaudeCacheParts(splitCacheRelative(tc.rel)); got != tc.want {
			t.Errorf("classifyClaudeCacheParts(%q) = %v, want %v", tc.rel, got, tc.want)
		}
	}
}

// stagingTestClock is a test clock for the staging code, safe across goroutines.
type stagingTestClock struct{ offset atomic.Int64 }

func (c *stagingTestClock) now() time.Time          { return time.Now().Add(time.Duration(c.offset.Load())) }
func (c *stagingTestClock) advance(d time.Duration) { c.offset.Add(int64(d)) }

// A staging folder is in flight while it was written (name stamp, newest
// modification time in it) in the last claudeStagingGrace, for
// claudeStagingCap at most: a slow clone is not quarantined mid-clone, and
// nothing stays unscanned past the cap. git's files in it count the same.
func TestClaudeInFlightWindow(t *testing.T) {
	cache := filepath.Join(t.TempDir(), ".claude", "plugins", "cache")
	w := claudeWatcher(t, cache)
	clock := &stagingTestClock{}
	w.stagingClock = clock.now
	stamped := func(at time.Time) string {
		return filepath.Join(cache, "temp_github_"+strconv.FormatInt(at.UnixMilli(), 10)+"_ab12")
	}

	idle := stamped(clock.now())
	mkdirs(t, filepath.Join(idle, "skills", "foo"))
	if !w.inClaudePluginStaging(filepath.Join(idle, "skills", "foo"), 0) {
		t.Fatal("a fresh staging folder is not in flight")
	}
	clock.advance(16 * time.Minute)
	if w.inClaudePluginStaging(filepath.Join(idle, "skills", "foo"), 0) {
		t.Fatal("a staging folder idle past the grace is still in flight")
	}

	slow := stamped(clock.now())
	pack := filepath.Join(slow, ".git", "objects", "pack", "tmp_pack_1")
	mkdirs(t, filepath.Dir(pack))
	if err := os.WriteFile(pack, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	began := clock.now()
	for clock.now().Sub(began) < claudeStagingCap-time.Minute {
		now := clock.now()
		if err := os.Chtimes(pack, now, now); err != nil {
			t.Fatal(err)
		}
		if !w.inClaudePluginStaging(filepath.Join(slow, ".git", "objects"), 0) {
			t.Fatalf("a clone still being written left flight after %s", clock.now().Sub(began))
		}
		clock.advance(14 * time.Minute)
	}
	now := clock.now()
	if err := os.Chtimes(pack, now, now); err != nil {
		t.Fatal(err)
	}
	if w.inClaudePluginStaging(filepath.Join(slow, ".git", "objects"), 0) {
		t.Fatal("a clone still being written stays in flight past the cap")
	}

	for name, folder := range map[string]string{
		"a stamp ahead of the clock":              stamped(clock.now().Add(10 * time.Minute)),
		"a stamp older than the cap, fresh write": stamped(clock.now().Add(-2 * time.Hour)),
	} {
		mkdirs(t, filepath.Join(folder, "a", "b"))
		if w.inClaudePluginStaging(filepath.Join(folder, "a", "b"), 0) {
			t.Errorf("%s is in flight", name)
		}
	}
}
