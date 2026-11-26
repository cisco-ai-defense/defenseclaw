// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package relay_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/workspace"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// plant puts programs in a folder the agent's user owns. Each one adds its
// name to mark, a file only root can make (base is root's 0755), and then
// runs the real program, so the review still works.
func (g *gap0795) plant(names ...string) (bin, mark string) {
	g.t.Helper()
	bin, mark = filepath.Join(g.base, "agentbin"), filepath.Join(g.base, "root-ran")
	if err := os.Mkdir(bin, 0o755); err != nil {
		g.t.Fatal(err)
	}
	for _, n := range names {
		real, err := exec.LookPath(n)
		if err != nil {
			g.t.Fatal(err)
		}
		p := filepath.Join(bin, n)
		body := fmt.Sprintf("#!/bin/sh\necho %s 2>/dev/null >> %s\nexec %s \"$@\"\n", n, mark, real)
		if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
			g.t.Fatal(err)
		}
		if err := os.Lchown(p, gap0795UID, gap0795UID); err != nil {
			g.t.Fatal(err)
		}
	}
	if err := os.Lchown(bin, gap0795UID, gap0795UID); err != nil {
		g.t.Fatal(err)
	}
	return bin, mark
}

// GAP-0795 H1 (RV-REG): the separated relay ran its review and push
// scripts as root with the image PATH, which may name a folder the agent
// can write (attest/envallow.go). A sh or git the agent put there ran as
// root. The relay now runs /bin/sh with a PATH of root-only folders.
func TestGAP0795RelayRootRunsNoAgentPathProgram(t *testing.T) {
	g := newGAP0795(t)
	g.write("app.txt", "work\n")
	g.git(g.repo, "add", ".")
	g.git(g.repo, "commit", "-qm", "work")
	head := g.git(g.repo, "rev-parse", "HEAD")
	g.handOver()
	bin, mark := g.plant("sh", "git", "cat", "awk", "sort", "mktemp")
	path := os.Getenv("PATH")
	t.Setenv("PATH", bin+":"+path)
	ctx := context.Background()
	p, err := workspace.PrepareBranchPush(ctx, g.run, filepath.Join(g.base, "work"), "a1", gap0795Origin, nil)
	var perr error
	if err == nil {
		perr = p.Push(ctx, g.run, "agent/fix", "a1", "")
		p.Discard(ctx, g.run)
	}
	os.Setenv("PATH", path)
	if b, rerr := os.ReadFile(mark); rerr == nil {
		runs := strings.Fields(string(b))
		seen := slices.Compact(slices.Sorted(slices.Values(runs)))
		t.Fatalf("the separated relay ran %d programs of an agent-writable PATH folder as root (%v)", len(runs), seen)
	}
	if err != nil {
		t.Fatalf("review: %v", err)
	}
	if perr != nil {
		t.Fatalf("push: %v", perr)
	}
	if got := g.git(g.base, "--git-dir", g.origin, "rev-parse", "refs/heads/agent/fix"); got != head {
		t.Fatalf("origin agent/fix %s, want %s", got, head)
	}
}

// GAP-0795 H1: a program only root may run must be root's alone, even in a
// root-only folder: a git the image gave the agent's user is refused, not
// run as root.
func TestGAP0795RelayRefusesAProgramTheAgentOwns(t *testing.T) {
	g := newGAP0795(t)
	g.write("app.txt", "work\n")
	g.git(g.repo, "add", ".")
	g.git(g.repo, "commit", "-qm", "work")
	g.handOver()
	bin, mark := g.plant("git")
	if err := os.Lchown(bin, 0, 0); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	ctx := context.Background()
	p, err := workspace.PrepareBranchPush(ctx, g.run, filepath.Join(g.base, "work"), "a1", gap0795Origin, nil)
	os.Setenv("PATH", strings.TrimPrefix(os.Getenv("PATH"), bin+":"))
	if _, rerr := os.Stat(mark); rerr == nil {
		t.Fatal("the separated relay ran a git the agent's user owns as root")
	}
	if err == nil {
		p.Discard(ctx, g.run)
		t.Fatal("the review ran with a git the agent's user owns first on PATH; want it refused")
	}
	t.Logf("refused: %v", err)
}

// GAP-0795 H2 (RV-REG): git attributes the agent controls must not change
// what the root review shows. A "-diff" attribute makes git treat a file as
// binary: no patch lines, and -G finds nothing, so a file that adds a
// credential placeholder was not flagged. The agent can write its HOME
// (~/.config/git/attributes, XDG_CONFIG_HOME), its checkout's
// .git/info/attributes and the commit's .gitattributes. A NUL byte in the
// file makes git read it as binary too ("nul"), so the flag scans read
// binary files as text.
func TestGAP0795ReviewIgnoresAgentAttributes(t *testing.T) {
	for _, tc := range []struct {
		name                string
		home, inCommit, nul bool
	}{
		{"home", true, false, false},
		{"repository", false, true, false},
		{"nul", false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := newGAP0795(t)
			const hide = "* -diff\n"
			if tc.inCommit {
				g.write(".gitattributes", hide)
			}
			body := "//r/:_authToken=" + kit.PlaceholderSecret + "\n"
			if tc.nul {
				body = "\x00" + body
				// A benign binary file stays unflagged.
				g.write("logo.bin", "\x00\x01plain bytes\n")
			}
			g.write("npmrc", body)
			g.git(g.repo, "add", ".")
			g.git(g.repo, "commit", "-qm", "work")
			if tc.inCommit {
				if err := os.WriteFile(filepath.Join(g.repo, ".git", "info", "attributes"), []byte(hide), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			g.handOver()
			if tc.home {
				home := filepath.Join(g.base, "home")
				gd := filepath.Join(home, ".config", "git")
				if err := os.MkdirAll(gd, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(gd, "attributes"), []byte(hide), 0o644); err != nil {
					t.Fatal(err)
				}
				if out, err := exec.Command("chown", "-R", fmt.Sprintf("%d:%d", gap0795UID, gap0795UID), home).CombinedOutput(); err != nil {
					t.Fatalf("chown: %v %s", err, out)
				}
				t.Setenv("HOME", home)
				t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
			}
			ctx := context.Background()
			p, err := workspace.PrepareBranchPush(ctx, g.run, filepath.Join(g.base, "work"), "a1", gap0795Origin, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Discard(ctx, g.run)
			if len(p.Placeholder) != 1 || p.Placeholder[0] != "npmrc" {
				t.Fatalf("placeholder files %d (%v), want npmrc: attributes the agent writes hid the commit from the root review", len(p.Placeholder), p.Placeholder)
			}
		})
	}
}
