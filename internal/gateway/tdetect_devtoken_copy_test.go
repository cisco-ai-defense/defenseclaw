// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"runtime"
	"testing"
	"time"
)

// TestOwnDeveloperTokenCopyKeepsTheRelTierFiveTiers pins the 30 cells of a
// copy of the active account's own .git-credentials, .netrc or .pgpass to a
// staging folder at the verdict rel 4269debe92 gives them: CRITICAL, a block
// in strict, managed and managed-strict, an alert in default and permissive,
// on the Claude Code hook and on /inspect/tool. The copy rule (b1d66c243c)
// made the typed owner prove a copy at the alert of the read, and the lane
// kept that alert, so the copy fell to alert MEDIUM (HIGH for .pgpass) and to
// allow in the permissive pack. The GAP-0888 ruling (one's own read keeps the
// tier of one's own AWS and kube files) covers reads only; the lead ruled on
// 2026-11-16 that a copy of these three files keeps the rel tier. The read
// keeps its own verdict (TestOwnDeveloperTokenReadIsJudgedLikeOwnCloudCredentialsFiveTiers).
func TestOwnDeveloperTokenCopyKeepsTheRelTierFiveTiers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home spellings")
	}
	const home = "/home/alice"
	t.Setenv("HOME", home)
	cwd := home + "/proj"
	want := map[string]string{
		"default": "alert", "permissive": "alert", "strict": "block", "managed": "block", "managed-strict": "block",
	}
	cells := 0
	for _, p := range gap0437Packs {
		hook := gap0437Server(t, p, "claudecode", "action")
		inspect := gap0437Server(t, p, "openclaw", "action")
		inspect.inspectToolScanTimeout = 30 * time.Second // policy semantics, not latency
		for _, file := range []string{".git-credentials", ".netrc", ".pgpass"} {
			command := fmt.Sprintf("cp %s/%s /tmp/staged", home, file)
			for route, out := range map[string]map[string]any{
				"hook-bash":    gap0437Hook(t, hook, cwd, "devtoken-copy-"+p.name+file, command),
				"inspect-exec": gap0437Inspect(t, inspect, cwd, command),
			} {
				cells++
				if out["action"] != want[p.name] || out["severity"] != "CRITICAL" {
					t.Errorf("%s %s %s: %v %v %v, want the rel verdict %s CRITICAL",
						p.name, route, file, out["action"], out["severity"], out["rule_ids"], want[p.name])
				}
			}
		}
	}
	if cells != 30 {
		t.Fatalf("judged %d cells, want 30", cells)
	}
}
