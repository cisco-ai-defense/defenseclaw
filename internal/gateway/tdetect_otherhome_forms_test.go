// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestOtherHomeCredentialFileSpellingsFiveTiers (rel-1-0-10:GAP-0837): the
// spellings that reach another account's home (~user, ~root, ../ from the
// working folder, a relative operand in a working folder that sits inside the
// other home) get the verdict of the absolute spelling of the same file, in the
// five tiers, through the Claude Code hook route and the OpenClaw /inspect/tool
// exec route. The strict pack blocks the SSH key in every spelling.
func TestOtherHomeCredentialFileSpellingsFiveTiers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home spellings (/home, /Users, /root) are read by the host's own path rules on native Windows; the C:\\Users forms are pinned by TestAccountHomeByPosition and TestOtherHomeCredentialFileShapes")
	}
	t.Setenv("HOME", "/home/alice")
	// A working folder that exists on the host, and ../ up to the root from it.
	realCwd := t.TempDir()
	up := strings.Repeat("../", strings.Count(strings.Trim(filepath.ToSlash(realCwd), "/"), "/")+1)
	for _, p := range gap0437Packs {
		hookServer := gap0437Server(t, p, "claudecode", "action")
		inspectServer := gap0437Server(t, p, "openclaw", "action")
		for _, file := range []string{".aws/credentials", ".netrc", ".git-credentials", ".ssh/id_rsa"} {
			for _, tc := range []struct{ name, cwd, command, oracle string }{
				{"tilde-user", "/home/alice/proj", "cat ~x/" + file, "/home/x/" + file},
				{"tilde-root", "/home/alice/proj", "cat ~root/" + file, "/root/" + file},
				{"dotdot", "/home/alice/proj", "cat ../../x/" + file, "/home/x/" + file},
				{"dotdot-real", realCwd, "cat " + up + "home/x/" + file, "/home/x/" + file},
				{"cwd-in-home", "/home/x", "cat " + file, "/home/x/" + file},
				{"cwd-below-home", "/home/x/proj", "cat ../" + file, "/home/x/" + file},
				{"cwd-in-root", "/root", "cat " + file, "/root/" + file},
			} {
				// The hook adapter reads a relative operand against a working
				// folder that exists on the host; these homes do not, so the
				// relative spellings are judged on the /inspect/tool route here
				// and at the owner (TestOtherHomeCredentialOwnersReadResolvedSpellings).
				relative := tc.name == "dotdot" || strings.HasPrefix(tc.name, "cwd")
				oracle := gap0437Hook(t, hookServer, "/home/alice/proj", p.name+"-or-"+tc.name+file, "cat "+tc.oracle)["action"]
				if file == ".ssh/id_rsa" && p.pack == "strict" && oracle != "block" {
					t.Errorf("%s %s: the absolute spelling of the key is %v, want block", p.name, tc.name, oracle)
				}
				if got := gap0437Hook(t, hookServer, tc.cwd, p.name+"-"+tc.name+file, tc.command)["action"]; !relative && td810Rank(got) < td810Rank(oracle) {
					t.Errorf("%s hook %s: %q is %v, weaker than %q (%v)", p.name, tc.name, tc.command, got, tc.oracle, oracle)
				}
				if got := gap0437Inspect(t, inspectServer, tc.cwd, tc.command)["action"]; td810Rank(got) < td810Rank(oracle) {
					t.Errorf("%s inspect %s: %q is %v, weaker than %q (%v)", p.name, tc.name, tc.command, got, tc.oracle, oracle)
				}
			}
		}
	}
}

// TestOtherHomeCredentialOwnersReadResolvedSpellings (rel-1-0-10:GAP-0837): the
// typed credential-file owners prove a read of another account's file when the
// call reaches it through ../ from the working folder, a relative operand in a
// working folder inside that home, or ~user and ~root.
func TestOtherHomeCredentialOwnersReadResolvedSpellings(t *testing.T) {
	for _, tc := range []struct{ owner, command, cwd string }{
		{"PATH-AWS-CREDS", "cat ../../x/.aws/credentials", "/home/alice/proj"},
		{"PATH-AWS-CREDS", "cat .aws/credentials", "/home/x"},
		{"PATH-AWS-CREDS", "cat ../.aws/credentials", "/home/x/proj"},
		{"PATH-AWS-CREDS", "cat ~x/.aws/credentials", "/home/alice/proj"},
		{"PATH-AWS-CREDS", "cat ~root/.aws/credentials", "/home/alice/proj"},
		{"PATH-GIT-CREDS", "cat ../../x/.netrc", "/home/alice/proj"},
		{"PATH-GIT-CREDS", "cat .netrc", "/home/x"},
		{"PATH-GIT-CREDS", "cat ~x/.git-credentials", "/home/alice/proj"},
		{"PATH-KUBE", "cat ../../x/.kube/config", "/home/alice/proj"},
		{"PATH-DOCKER", "cat ~x/.docker/config.json", "/home/alice/proj"},
	} {
		facts := actionfacts.Analyze(actionfacts.Input{Tool: "Bash", Command: tc.command, CWD: tc.cwd, ActiveHome: "/home/alice", DialectHint: actionfacts.DialectPOSIX})
		owner, ok := semanticOwners[tc.owner]
		if !ok {
			t.Fatalf("no semantic owner %s", tc.owner)
		}
		if !owner.eligible(facts) {
			t.Errorf("%s does not prove the read of %q (cwd %s)", tc.owner, tc.command, tc.cwd)
		}
	}
	// A project folder named like a home is no home, from any working folder.
	for _, tc := range []struct{ command, cwd string }{
		{"cat users/bob/.aws/credentials", "/work/repo"},
		{"cat ./home/bob/.netrc", "/home/ci/work"},
		{"cat /work/repo/Users/bob/.aws/credentials", "/elsewhere"},
	} {
		facts := actionfacts.Analyze(actionfacts.Input{Tool: "Bash", Command: tc.command, CWD: tc.cwd, ActiveHome: "/home/alice", DialectHint: actionfacts.DialectPOSIX})
		for _, id := range []string{"PATH-AWS-CREDS", "PATH-GIT-CREDS"} {
			if semanticOwners[id].eligible(facts) {
				t.Errorf("%s proves a read of %q (cwd %s): a project folder is no account home", id, tc.command, tc.cwd)
			}
		}
	}
}
