// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package managed

import "testing"

// rel-1-0-10:GAP-1541: without DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR (an
// administrator shell), the macOS standalone data directory resolves to the
// hook-guardian-state directory its lifecycle creates and its plists name,
// not to a <data_dir>-hook-guardian that does not exist there. Every other
// data directory keeps <data_dir>-hook-guardian. The cases are the Linux and
// macOS layouts' slash paths, which filepath.Clean rewrites on a Windows
// host, so the test builds only off Windows (Windows has no such layout).
func TestHookGuardianAuthorizationDirFollowsTheMacStandaloneLayout(t *testing.T) {
	layout, err := StandaloneLayoutFor("darwin")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ goos, dataDir, want string }{
		{"darwin", layout.DataDir, layout.GuardianAuthDir},
		{"darwin", layout.DataDir + "/", layout.GuardianAuthDir},
		{"darwin", "/Users/alice/.defenseclaw", "/Users/alice/.defenseclaw-hook-guardian"},
		{"linux", "/var/lib/defenseclaw", "/var/lib/defenseclaw-hook-guardian"},
		{"linux", layout.DataDir, layout.DataDir + "-hook-guardian"},
	} {
		if got := hookGuardianAuthorizationDirFor(tc.goos, tc.dataDir); got != tc.want {
			t.Errorf("%s %q: got %q, want %q", tc.goos, tc.dataDir, got, tc.want)
		}
	}
	linux, err := StandaloneLayoutFor("linux")
	if err != nil {
		t.Fatal(err)
	}
	if got := hookGuardianAuthorizationDirFor("linux", linux.DataDir); got != linux.GuardianAuthDir {
		t.Errorf("the Linux standalone layout already pairs by suffix: got %q, want %q", got, linux.GuardianAuthDir)
	}
}
