// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"strconv"
	"strings"
)

// A per-user rollback runs the setup and, later, the teardown of the earlier
// release over the agent files this release wrote. Both match the DefenseClaw
// hook entries by the exact command that release renders, so an entry in any
// other form is foreign to it: its setup adds its own entry beside it, and its
// teardown leaves it behind (the GAP-1284 rule). A rollback converter
// therefore writes, for each entry, the exact command the TARGET release
// renders, not one earlier form for every target (rel-1-0-10:GAP-0275 for
// Kiro, rel-1-0-10:GAP-0759 for Codex: 22 Codex handlers after a rollback to
// 1.0.5). These are the releases that first rendered each per-user Windows
// form, taken from the renders of every release tag (testdata
// *_windows_release_hook_forms.json); a release renders and owns every form
// from its first release on.
var (
	// The direct system cmd.exe start of the launcher (GAP-1908).
	releaseCodexDirectStart = releaseVersion{1, 0, 5}
	// The Constrained Language fallback end that exits 1 when the launcher
	// never started (windowsAwaitedHookFallbackExit); earlier releases
	// render and own only legacyWindowsAwaitedHookFallbackExit.
	releaseCurrentAwaitedFallback = releaseVersion{1, 0, 8}
	// The launcher-start answer: the Codex and Devin guarded starts and the
	// answering bridges (rel-1-0-6 GAP-0676). A target from here on writes
	// what this release writes, so a rollback to it converts nothing.
	releaseLauncherStartAnswer = releaseVersion{1, 0, 9}
)

// releaseVersion is a DefenseClaw release number (major, minor, patch).
type releaseVersion [3]int

// parseReleaseVersion reads a DefenseClaw release number such as "1.0.5",
// "v1.0.8" or "1.0.6-rc.dm2".
func parseReleaseVersion(value string) (releaseVersion, bool) {
	value = strings.TrimPrefix(strings.TrimSpace(value), "v")
	if cut := strings.IndexAny(value, "-+ "); cut >= 0 {
		value = value[:cut]
	}
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return releaseVersion{}, false
	}
	var version releaseVersion
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return releaseVersion{}, false
		}
		version[i] = n
	}
	return version, true
}

// rollbackTargetOwns reports whether the rollback target release renders
// (and so owns) the form first rendered by first. An unknown or unparsable
// target owns none of them: the converters then write the form every 1.0.x
// release owns.
func rollbackTargetOwns(target string, first releaseVersion) bool {
	version, ok := parseReleaseVersion(target)
	if !ok {
		return false
	}
	for i := range version {
		if version[i] != first[i] {
			return version[i] > first[i]
		}
	}
	return true
}
