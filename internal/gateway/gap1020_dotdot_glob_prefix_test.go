// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// gap1020Verdict is the Claude Code hook action for one Bash command run
// from project, as A (allow), L (alert) or B (block).
func gap1020Verdict(t *testing.T, a *APIServer, pack, project, command string) string {
	t.Helper()
	out := gap0437Serve(t, a.handleAgentHook("claudecode"), "/api/v1/claude-code/hook", map[string]any{
		"hook_event_name": "PreToolUse", "session_id": "gap1020-" + pack, "cwd": project,
		"tool_name": "Bash", "tool_use_id": "tu-" + command, "tool_input": map[string]any{"command": command},
	})
	action, _ := out["action"].(string)
	return map[string]string{"allow": "A", "alert": "L", "block": "B"}[action]
}

// rel-1-0-10:GAP-1020: a pattern operand whose path walks into a real folder
// and back out (x/../, ./x/../, proj/../) names the folder the dot-dot leads
// to, so it gets the verdict of the plain spelling. Before the fix the hook's
// name match compared the spelling, dot-dot as a name, with the key and
// authorized keys paths: after cd .. into the home, cat, base64, mv and rm of
// x/../.ssh/* and x/../.ssh/./* were allowed and x/../.*/* allowed or alerted
// where .ssh/* and .*/* block (58 of 600 cells per prefix, all five packs).
// The same holds for a relative ../ operand with no cd.
func TestGAP1020DotDotPrefixGlobKeepsPlainVerdict(t *testing.T) {
	home, project := cdFirstFixture(t)
	if err := os.MkdirAll(filepath.Join(home, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	bases := []string{".ssh/*", ".ssh/./*", ".*/*"}
	verbs := []string{"cat %s", "base64 %s", "cp %s /tmp/staged", "mv %s /tmp/staged", "rm -f %s"}
	forms := []struct{ cd, lead string }{{"cd .. && ", ""}, {"", "../"}}
	for _, p := range gap0437Packs {
		a := gap0437Server(t, p, "claudecode", "action")
		for _, form := range forms {
			for _, base := range bases {
				for _, verb := range verbs {
					plainCommand := form.cd + strings.Replace(verb, "%s", form.lead+base, 1)
					plain := gap1020Verdict(t, a, p.name, project, plainCommand)
					if base == ".ssh/*" && verb == "cat %s" && plain != "B" {
						t.Fatalf("%s: %q is %s, want the key read blocked (B)", p.name, plainCommand, plain)
					}
					for _, prefix := range []string{"x/../", "./x/../", "proj/../"} {
						command := form.cd + strings.Replace(verb, "%s", form.lead+prefix+base, 1)
						if got := gap1020Verdict(t, a, p.name, project, command); got != plain {
							t.Errorf("%s: %q is %s, the plain spelling %q is %s", p.name, command, got, plainCommand, plain)
						}
					}
				}
			}
		}
	}
}

// rel-1-0-10:GAP-1020, never stronger: the dot-dot steps are applied the way
// the kernel opens the path, so a link's dot-dot leads beside the link's
// target, not back into the home (link/../.ssh/* is the .ssh folder of the
// target's parent, which holds no key of the user), and a benign folder
// spelled through a dot-dot keeps the plain verdict.
func TestGAP1020DotDotPrefixGlobFollowsLinksAndStaysBenign(t *testing.T) {
	home, project := cdFirstFixture(t)
	outside := filepath.Join(t.TempDir(), "elsewhere", "dir")
	for _, dir := range []string{filepath.Join(home, "x"), filepath.Join(home, "notes"), outside} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, "notes", "todo.txt"), []byte("todo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(home, "link")); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
	beside := filepath.Join(filepath.Dir(outside), ".ssh")
	for _, p := range gap0437Packs {
		a := gap0437Server(t, p, "claudecode", "action")
		for _, verb := range []string{"cat %s", "rm -f %s", "mv %s /tmp/staged"} {
			for spelled, plain := range map[string]string{
				"cd .. && " + strings.Replace(verb, "%s", "link/../.ssh/*", 1):  strings.Replace(verb, "%s", beside+"/*", 1),
				"cd .. && " + strings.Replace(verb, "%s", "x/../notes/*", 1):    "cd .. && " + strings.Replace(verb, "%s", "notes/*", 1),
				"cd .. && " + strings.Replace(verb, "%s", "proj/../notes/*", 1): "cd .. && " + strings.Replace(verb, "%s", "notes/*", 1),
			} {
				want := gap1020Verdict(t, a, p.name, project, plain)
				if got := gap1020Verdict(t, a, p.name, project, spelled); got != want {
					t.Errorf("%s: %q is %s, the spelling it opens %q is %s", p.name, spelled, got, plain, want)
				}
			}
		}
	}
}
