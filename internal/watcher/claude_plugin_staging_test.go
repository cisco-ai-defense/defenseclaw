// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"strconv"
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
		// git's files in a staging clone.
		{`temp_subdir_` + ts + `_t2ymk0.clone/.git`, claudeCacheStagingGit},
		{`temp_subdir_` + ts + `_t2ymk0.clone/.git/hooks`, claudeCacheStagingGit},
		{`temp_subdir_` + ts + `_t2ymk0.clone\.git\objects`, claudeCacheStagingGit},
		{`temp_github_` + ts + `_ab12/.git/refs`, claudeCacheStagingGit},
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

// A staging folder is in flight only while the time stamp in its name is
// recent: an old or far-future name is read as a plugin again.
func TestClaudeStagingFresh(t *testing.T) {
	now := time.Now()
	name := func(at time.Time) string {
		return "temp_github_" + strconv.FormatInt(at.UnixMilli(), 10) + "_ab12"
	}
	for _, tc := range []struct {
		name string
		want bool
	}{
		{name(now), true},
		{name(now.Add(-14 * time.Minute)), true},
		{name(now.Add(30 * time.Second)), true},
		{name(now.Add(-16 * time.Minute)), false},
		{name(now.Add(-24 * time.Hour)), false},
		{name(now.Add(10 * time.Minute)), false},
		{"temp_github_99999999999999999999_ab12", false},
		{"mkt", false},
	} {
		if got := claudeStagingFresh(tc.name, now); got != tc.want {
			t.Errorf("claudeStagingFresh(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}
