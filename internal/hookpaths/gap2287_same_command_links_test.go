// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// GAP-2287: a write through a link the same command makes keeps the spelling
// the kernel follows, so the write proofs resolve the link first: a dot-dot
// that steps out of the link, and a plain write through a link to a process
// link. Without the link, the dot-dot is cleaned as before (GAP-2274), and a
// mv/install/rsync destination outside process links is not listed
// (GAP-2275).
func TestGAP2287LiteralWritesKeepSameCommandLinkSteps(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX folders and process links: Windows has no /proc and reads a dot-dot step lexically (dotDotReadsLexically)")
	}
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
	if runtime.GOOS == "windows" {
		// The walk reads POSIX placed paths only: Windows reads a dot-dot
		// step after a link lexically (dotDotReadsLexically).
		return
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
		// The folder in the shell spelling an agent writes (C:/... on Windows).
		for _, dest := range []string{" x/../.claude/settings.json", " " + filepath.ToSlash(cwd) + "/x/../.claude/settings.json"} {
			command := writer + dest
			if writer == "mv -t x/../.claude /tmp/settings.json" {
				command = writer
			}
			got := DotDotMoveDestinations(command, cwd, home)
			for i := range got {
				got[i] = filepath.FromSlash(got[i])
			}
			if !slices.Equal(got, []string{want}) {
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

// CHK-T6-2287 H1: once the command makes a link, linkBeforeStep read each
// part of a placed path by joining every part before it, so a long path cost
// its length squared: a 60 KB command (under actionfacts.MaxCommandBytes) took
// seconds. The walk keeps a running prefix now, so it costs one pass.
func TestGAP2287LinkBeforeStepScale(t *testing.T) {
	const cwd, home = "/sandbox/app", "/sandbox"
	long := strings.Repeat("d/", 29000)
	made := madeLinks{"/w/L": "/srv/out"}
	for _, path := range []string{"/w/L/" + long + "f", "/w/L/" + long + "../f", "/w/" + long[:40000] + strings.Repeat("x/../", 3000) + "f"} {
		if allocs := testing.AllocsPerRun(3, func() { made.linkBeforeStep(path) }); allocs > 64 {
			t.Errorf("linkBeforeStep of a %d-byte path: %.0f allocations, want a few (one pass, not one per part)", len(path), allocs)
		}
	}
	if runtime.GOOS == "windows" {
		// The command rows place POSIX folders, which a Windows host does not
		// read (TestGAP2287LiteralWritesKeepSameCommandLinkSteps).
		return
	}
	for _, row := range []struct {
		name string
		run  func() int
	}{
		{"cp through a made link", func() int {
			return len(LiteralWriteOperands("ln -s /srv/out L && cp a.txt L/"+long+"f", cwd, home))
		}},
		{"mv dot-dot through a made link", func() int {
			return len(LiteralWriteOperands("ln -s /srv/out L && mv a.txt L/"+long+"../f", cwd, home))
		}},
		{"guard mv dot-dot through a made link", func() int {
			return len(DotDotMoveDestinations("ln -s /srv/out L && mv a.txt L/"+long+"../f", cwd, home))
		}},
	} {
		best := time.Duration(1 << 62)
		for range 3 {
			start := time.Now()
			if row.run() == 0 {
				t.Errorf("%s: no write read", row.name)
			}
			best = min(best, time.Since(start))
		}
		t.Logf("%s: %v", row.name, best)
		if best > 250*time.Millisecond {
			t.Errorf("%s, a %d-byte path: %v, want one pass (well under 250ms)", row.name, len(long), best)
		}
	}
}
