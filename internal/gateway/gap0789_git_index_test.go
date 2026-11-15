// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// GAP-0789 (review s7-g596brev of s7/sshfp edbbaf0773): GIT_INDEX_FILE or
// GIT_DIR before git checkout -- . or git restore . moves the index git reads
// away from <worktree>/.git/index, so the hook settings file a folder lacks
// may still be restored from it. Rows G01, G02, G04 and G05 keep rel's
// verdict in all five tiers; G07 (no variable, no index file) stays allowed.
func TestGAP0789MovedIndexKeepsTheHookFinding(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell rows")
	}
	home, _ := shellProtectedFileHome(t)
	work := filepath.Join(home, "td", "work", "default")
	hooked := filepath.Join(work, "hooked")
	hooked3 := filepath.Join(work, "hooked3")
	for _, dir := range []string{filepath.Join(hooked, ".git"), filepath.Join(hooked, ".claude"), filepath.Join(hooked3, ".git")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	sshfp2WriteIndex(t, filepath.Join(hooked, ".git", "index"), 2, ".claude/settings.json", "src/main.go")
	index := filepath.Join(hooked, ".git", "index")
	gitDir := filepath.Join(hooked, ".git")
	sshfp2Run(t, home, []sshfp2Row{
		{"G01 GIT_INDEX_FILE prefix", hooked3, fmt.Sprintf("GIT_INDEX_FILE=%s git checkout -- .", index), sshfp2Hook, sshfp2Warn},
		{"G02 env GIT_INDEX_FILE", hooked3, fmt.Sprintf("env GIT_INDEX_FILE=%s git checkout -- .", index), sshfp2Hook, sshfp2Warn},
		{"G04 export GIT_INDEX_FILE", hooked3, fmt.Sprintf("export GIT_INDEX_FILE=%s; git restore .", index), sshfp2Hook, sshfp2Warn},
		{"G05 GIT_DIR prefix", hooked3, fmt.Sprintf("GIT_DIR=%s git checkout -- .", gitDir), sshfp2Hook, sshfp2Warn},
		{"G08 GIT_DIR restore", hooked3, fmt.Sprintf("GIT_DIR=%s git restore .", gitDir), sshfp2Hook, sshfp2Warn},
		{"G09 declare -x then restore", hooked3, fmt.Sprintf("declare -x GIT_INDEX_FILE=%s; git restore -- .", index), sshfp2Hook, sshfp2Warn},
		// The index-less twin and a plain checkout stay allowed (GAP-0572).
		{"G07 checkout -- . (no index file)", hooked3, "git checkout -- .", "", sshfp2Allow},
		{"G10 restore . (no index file)", hooked3, "git restore .", "", sshfp2Allow},
	})
}
