// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// GAP-2287: a write through a link the same command makes keeps the spelling
// the kernel follows, so the write proofs resolve the link first: a dot-dot
// that steps out of the link, and a plain write through a link to a process
// link. Without the link, the dot-dot is cleaned as before (GAP-2274), and a
// mv/install/rsync destination outside process links is not listed
// (GAP-2275).
func TestGAP2287LiteralWritesKeepSameCommandLinkSteps(t *testing.T) {
	const cwd, home = "/sandbox/app", "/sandbox"
	key := "authorized_" + "keys"
	for _, writer := range []string{"mv /tmp/k", "install /tmp/k", "rsync /tmp/k", "cp /tmp/k"} {
		for _, row := range []struct{ link, dest, want string }{
			{"ln -s /proc/self/cwd L", "L/../.ssh/" + key, cwd + "/L/../.ssh/" + key},
			{"ln -s /proc/self/cwd/.. L", "L/.ssh/" + key, cwd + "/L/.ssh/" + key},
			{"ln -s /sandbox/.ssh/x L", "L/../" + key, cwd + "/L/../" + key},
		} {
			command := row.link + " && " + writer + " " + row.dest
			if got := LiteralWriteOperands(command, cwd, home); !slices.Contains(got, row.want) {
				t.Errorf("%q: literal writes %q, want %s among them", command, got, row.want)
			}
		}
	}
	for _, command := range []string{
		"mv a.txt x/../notes.txt",
		"install a.txt x/../notes.txt",
		"rsync -a src/ x/../backup/",
	} {
		if got := LiteralWriteOperands(command, cwd, home); len(got) != 0 {
			t.Errorf("%q: literal writes %q, want none (GAP-2275)", command, got)
		}
	}
	// A plain write through a link to a plain folder stays with the link
	// reader; only the link name of the ln call is listed.
	if got := LiteralWriteOperands("ln -s /sandbox/out L && mv a.txt L/b.txt", cwd, home); slices.Contains(got, cwd+"/L/b.txt") {
		t.Errorf("a move through a link to a plain folder is listed: %q", got)
	}
	if got := LiteralWriteOperands("cp a.txt x/../notes.txt", cwd, home); !slices.Equal(got, []string{cwd + "/notes.txt"}) {
		t.Errorf("cp through a plain x/..: literal writes %q, want the cleaned name (GAP-2274)", got)
	}
}

func TestGAP2287LinkBeforeStep(t *testing.T) {
	made := madeLinks{"/w/L": "/proc/self/cwd", "/w/P": "/srv/plain"}
	for _, row := range []struct {
		path string
		want bool
	}{
		{"/w/L/x", true},
		{"/w/P/../x", true},
		{"/w/P/x", false},
		{"/w/Q/../x", false},
		{"/w/x", false},
		{"rel/../x", false},
	} {
		if got := made.linkBeforeStep(row.path); got != row.want {
			t.Errorf("linkBeforeStep(%q) = %t, want %t", row.path, got, row.want)
		}
	}
	var none madeLinks
	if none.linkBeforeStep("/w/L/x") {
		t.Error("no made link and no dot-dot: no link to follow")
	}
	dir := t.TempDir()
	if err := os.Symlink(filepath.Join(dir, "real"), filepath.Join(dir, "disk")); err != nil {
		t.Skip(err)
	}
	if !none.linkBeforeStep(filepath.Join(dir, "disk") + "/../x") {
		t.Error("a dot-dot after a link on disk keeps its spelling")
	}
}

// GAP-2288: the hook config guard gets the cleaned destination of a move,
// install or sync spelled through x/.., and nothing for a plain spelling.
func TestGAP2288DotDotMoveDestinations(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "app")
	want := filepath.Join(cwd, ".claude", "settings.json")
	for _, writer := range []string{"mv /tmp/s", "install /tmp/s", "rsync /tmp/s", "install -m 600 /tmp/s", "mv -t x/../.claude /tmp/settings.json"} {
		for _, dest := range []string{" x/../.claude/settings.json", " " + cwd + "/x/../.claude/settings.json"} {
			command := writer + dest
			if writer == "mv -t x/../.claude /tmp/settings.json" {
				command = writer
			}
			if got := DotDotMoveDestinations(command, cwd, home); !slices.Equal(got, []string{want}) {
				t.Errorf("%q: %q, want [%s]", command, got, want)
			}
		}
	}
	for _, command := range []string{"mv /tmp/s .claude/settings.json", "cp /tmp/s x/../.claude/settings.json", "mv /tmp/s $D/../x"} {
		if got := DotDotMoveDestinations(command, cwd, home); len(got) != 0 {
			t.Errorf("%q: %q, want none", command, got)
		}
	}
}
