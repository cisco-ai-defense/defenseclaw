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

// rel-1-0-10:GAP-2241: a dot-dot step out of a link into the home leads where
// the kernel opens it, the folder above the link's target. With lp a link to
// ~/proj and lx a link to ~/x, lp/../.ssh/* and lx/../.ssh/* after cd .. name
// ~/.ssh/* and get the plain verdict, quoted or not. Before the fix the step
// out of any link kept the spelling, so with an empty .ssh only the host
// expansion decided and found nothing: allow where .ssh/* blocks by name.
func TestGAP2241DotDotAfterLinkIntoHomeKeepsPlainVerdict(t *testing.T) {
	home, project := cdFirstFixture(t)
	if err := os.MkdirAll(filepath.Join(home, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{"lp": project, "lx": filepath.Join(home, "x")} {
		if err := os.Symlink(target, filepath.Join(home, link)); err != nil {
			t.Skipf("no symlinks here: %v", err)
		}
	}
	bases := []string{".ssh/*", ".ssh/./*", ".*/*"}
	verbs := []string{"cat %s", "base64 %s", "cp %s /tmp/staged", "mv %s /tmp/staged", "rm -f %s"}
	for _, p := range gap0437Packs {
		a := gap0437Server(t, p, "claudecode", "action")
		for _, base := range bases {
			for _, verb := range verbs {
				plainCommand := "cd .. && " + strings.Replace(verb, "%s", base, 1)
				plain := gap1020Verdict(t, a, p.name, project, plainCommand)
				if base == ".ssh/*" && verb == "cat %s" && plain != "B" {
					t.Fatalf("%s: %q is %s, want the key read blocked (B)", p.name, plainCommand, plain)
				}
				for _, prefix := range []string{"lp/../", "lx/../", "./lp/../", `"lp/.."/`, "lp/.git/../../"} {
					command := "cd .. && " + strings.Replace(verb, "%s", prefix+base, 1)
					if got := gap1020Verdict(t, a, p.name, project, command); got != plain {
						t.Errorf("%s: %q is %s, the plain spelling %q is %s", p.name, command, got, plainCommand, plain)
					}
				}
			}
		}
	}
}

// rel-1-0-10:GAP-2241, never stronger: a step out of a link that names no
// folder (a link to a file, a dangling link) opens nothing, as before, and a
// link to a folder outside the home steps beside its target.
func TestGAP2241DotDotAfterLinkStaysWhereTheKernelLeads(t *testing.T) {
	home, project := cdFirstFixture(t)
	outside := filepath.Join(t.TempDir(), "elsewhere", "dir")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "notes.txt"), []byte("todo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{
		"lout": outside, "lfile": filepath.Join(home, "notes.txt"), "ldangling": filepath.Join(home, "gone"),
	} {
		if err := os.Symlink(target, filepath.Join(home, link)); err != nil {
			t.Skipf("no symlinks here: %v", err)
		}
	}
	beside := filepath.Join(filepath.Dir(outside), ".ssh")
	for _, p := range gap0437Packs {
		a := gap0437Server(t, p, "claudecode", "action")
		for _, verb := range []string{"cat %s", "rm -f %s"} {
			for spelled, opened := range map[string]string{
				"cd .. && " + strings.Replace(verb, "%s", "lout/../.ssh/*", 1):      strings.Replace(verb, "%s", beside+"/*", 1),
				"cd .. && " + strings.Replace(verb, "%s", "lfile/../notes.tx?", 1):  "cd .. && " + strings.Replace(verb, "%s", "lfile/../notes.tx?", 1),
				"cd .. && " + strings.Replace(verb, "%s", "ldangling/../.ssh/*", 1): "cd .. && " + strings.Replace(verb, "%s", "nosuch/../.ssh/*", 1),
			} {
				want := gap1020Verdict(t, a, p.name, project, opened)
				if got := gap1020Verdict(t, a, p.name, project, spelled); got != want {
					t.Errorf("%s: %q is %s, the spelling it opens %q is %s", p.name, spelled, got, opened, want)
				}
			}
		}
	}
}
