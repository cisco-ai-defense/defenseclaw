// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// s7-probe2 old-API probe for rel-1-0-10:GAP-0834: the rel hook-route tests of the fix,
// copied with only the rel test helpers the pre-fix sha 51e38bfab3 lacks (renamed),
// so the file compiles on the pre-fix tree and on rel. Scratch, test-only branch.

package gateway

import (
	"runtime"
	"slices"
	"strings"
	"testing"
)

// TestOtherHomeCredentialFileCopyFiveTiers (rel-1-0-10:GAP-0834): the typed
// credential-file owners prove a read in any account home, but a copy of
// another account's file is not a read they prove; with the other homes inside
// the owners' safe negative, the regex fallback that judged the copy on rel was
// dropped and it became a clean allow. In the five tiers, through the hook and
// the /inspect/tool route, a copy of another account's file has at least the
// verdict of a copy of the active account's same file, and at least the alert of
// rel where the regex roots alerted (every tier but permissive).
func TestCCP2G0834_OtherHomeCredentialFileCopyFiveTiers(t *testing.T) {
	ccp2g0834_td810OtherHomeFiles(t, func(pack string, hook, inspect func(id, command string) any, file, home string) {
		path := home + "/" + file
		active := hook("cp-act-"+file, ccp2g0834_td810CopyCommand("/home/alice/"+file))
		for route, got := range map[string]any{
			"hook":    hook("cp-"+path, ccp2g0834_td810CopyCommand(path)),
			"inspect": inspect("", ccp2g0834_td810CopyCommand(path)),
		} {
			if ccp2g0834_td810Rank(got) < ccp2g0834_td810Rank(active) {
				t.Errorf("%s %s: copy of %s is %v, weaker than the copy of the active file (%v)", pack, route, path, got, active)
			}
			if pack != "permissive" && !slices.Contains([]string{".git-credentials", ".netrc"}, file) && ccp2g0834_td810Rank(got) < 1 {
				t.Errorf("%s %s: copy of %s is %v, want at least the rel alert", pack, route, path, got)
			}
		}
	})
}

// td810CopyCommand and td810UploadCommand spell the two transfers the
// GAP-0834/0835 rows send for a file: a local copy and a form upload to an
// external host (the shapes of the s7-td810rev probe rows cp:* and egress:*).
func ccp2g0834_td810CopyCommand(file string) string {
	return strings.Join([]string{"cp", file, "/tmp/td810-copy"}, " ")
}

// td810OtherHomeFiles runs check, in the five tiers, for each credentials file
// of each other account home the regex roots of rel judged (/home/<u>,
// /Users/<u>, /root), with the Claude Code hook route and the OpenClaw
// /inspect/tool exec route of the tier.
func ccp2g0834_td810OtherHomeFiles(t *testing.T, check func(pack string, hook, inspect func(id, command string) any, file, home string)) {
	t.Helper()
	t.Setenv("HOME", "/home/alice")
	files := []string{".aws/credentials", ".kube/config", ".docker/config.json", ".git-credentials", ".netrc"}
	for _, p := range gap0437Packs {
		hookServer := gap0437Server(t, p, "claudecode", "action")
		inspectServer := gap0437Server(t, p, "openclaw", "action")
		cwd := t.TempDir()
		hook := func(id, command string) any {
			t.Helper()
			return gap0437Hook(t, hookServer, cwd, p.name+"-"+id, command)["action"]
		}
		inspect := func(_, command string) any {
			t.Helper()
			return gap0437Inspect(t, inspectServer, cwd, command)["action"]
		}
		for _, file := range files {
			for _, home := range []string{"/home/x", "/Users/x", "/root"} {
				if runtime.GOOS == "windows" && home == "/root" {
					// /root is not an absolute path on a Windows host.
					continue
				}
				check(p.name, hook, inspect, file, home)
			}
		}
	}
}

// td810Rank orders the answers of a hook or /inspect/tool call.
func ccp2g0834_td810Rank(action any) int {
	switch action {
	case "block":
		return 2
	case "alert":
		return 1
	}
	return 0
}
