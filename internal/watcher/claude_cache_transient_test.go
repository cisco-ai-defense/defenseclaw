// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import "testing"

// Issue #1428: the name test is on the folder names relative to the cache, so
// it reads POSIX and Windows separators, and the mixed-case names NTFS and
// APFS keep, the same on every host.
func TestClaudeCacheTransientParts(t *testing.T) {
	for _, tc := range []struct {
		rel  string
		want bool
	}{
		// Claude Code's "plugin update" staging clone and everything in it.
		{`temp_subdir_1793946491108_t2ymk0.clone`, true},
		{`temp_subdir_1793946491108_t2ymk0.clone/.git/hooks`, true},
		{`temp_subdir_1793946491108_t2ymk0.clone\.git\objects`, true},
		{`temp_subdir_1793946491108_t2ymk0.clone\plugins\sample`, true},
		{`TEMP_SUBDIR_1_AB.CLONE/plugins/sample`, true},
		// Any .git folder.
		{`mkt/plugin/.git`, true},
		{`mkt\plugin\.git\objects`, true},
		{`.git`, true},
		{`mkt/.GIT/hooks`, true},
		// Real plugins and near misses stay plugins.
		{`mkt/plugin/1.0.0`, false},
		{`mkt\plugin\1.0.0`, false},
		{`openai-curated-remote/github/1.2.0`, false},
		{`temp_subdir_1_ab`, false},
		{`temp_subdir_.clone`, false},
		{`mkt/temp_subdir_1_ab.clone/1.0.0`, false},
		{`temp_local_1759900000000/skills/x`, false},
		{`mkt/plugin/.github`, false},
		{`mkt/plugin/1.0.0/.gitignore`, false},
		{`mkt/my.git/1.0.0`, false},
		{`mkt/plugin/gitx`, false},
		{``, false},
	} {
		if got := claudeCacheTransientParts(splitCacheRelative(tc.rel)); got != tc.want {
			t.Errorf("claudeCacheTransientParts(%q) = %v, want %v", tc.rel, got, tc.want)
		}
	}
}
