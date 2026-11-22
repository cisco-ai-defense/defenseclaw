// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package workspace

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	osw "github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

// GAP-0575 (GAP-0530 residual): the NTFS forms of .git (GIT~1, git~1,
// .git. and .git followed by a space), which git refuses on every
// platform (core.protectNTFS), still failed the whole pull with "invalid
// path". They are git metadata too: left out, named in the review, never
// written by an apply.
func TestGAP0575NTFSGitNamesAreLeftOutNotFatal(t *testing.T) {
	for name, p := range map[string]string{
		"GIT~1/hooks/pre-commit":   "GIT~1/hooks/pre-commit",
		".git./hooks/pre-commit":   ".git./hooks/pre-commit",
		"'.git '/hooks/pre-commit": ".git /hooks/pre-commit",
		"sub/git~1/config":         "sub/git~1/config",
	} {
		t.Run(name, func(t *testing.T) {
			o, sb, _ := copyInActor(t)
			ctx := context.Background()
			agent := sb.local(remoteProject)
			write(t, agent, "README.md", "agent version\n", 0o644)
			full := filepath.Join(agent, filepath.FromSlash(p))
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(full, []byte("#!/bin/sh\nid\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			rv, err := Pull(ctx, PullOptions{Exec: sb, DataDir: o.data, Name: "c1"})
			if err != nil {
				t.Fatalf("the pull failed: %v", err)
			}
			top := strings.SplitN(p, "/", 2)[0]
			if strings.HasPrefix(p, "sub/") {
				top = "sub/git~1"
			}
			named := false
			for _, w := range rv.Warnings {
				if strings.Contains(w, "left out, never brought back") && strings.Contains(w, top) {
					named = true
				}
			}
			if !named {
				t.Errorf("the review does not name %q as left out: %q", top, rv.Warnings)
			}
			for _, c := range rv.Changed {
				if strings.Contains(strings.ToLower(c.Path), strings.ToLower(top)) {
					t.Errorf("review lists git metadata as a change: %s", c.Path)
				}
			}
			if _, err := Apply(ctx, ApplyOptions{DataDir: o.data, Name: "c1", Mode: ModeApply, AcceptSensitive: true}); err != nil {
				t.Fatalf("apply: %v", err)
			}
			if read(t, o.project, "README.md") != "agent version\n" {
				t.Error("the rest of the work was not brought back")
			}
			if _, err := os.Lstat(filepath.Join(o.project, filepath.FromSlash(p))); err == nil {
				t.Errorf("%s was carried into the folder", p)
			}
		})
	}
}

// Host copy takes the same rule (git's is_ntfs_dotgit).
func TestGAP0575HostCopyNTFSGitNames(t *testing.T) {
	for p, want := range map[string]bool{
		"GIT~1/hooks/pre-commit": true, "sub/git~1/config": true, ".git./config": true, ".git /config": true,
		".Git/config": true, "a/.git": true, ".gitignore": false, ".github/workflows/x.yml": false, "git~2/x": false,
		".git-blame-ignore-revs": false, "src/git~1.txt": false,
	} {
		if got := hasGitComponent(p); got != want {
			t.Errorf("hasGitComponent(%q) = %v, want %v", p, got, want)
		}
	}
}

// The apply refusal names only the changes that gate it: an info-only
// in-project link (lib -> src) is not one that can run code.
func TestGAP0575RefusalNamesOnlyGatingFlags(t *testing.T) {
	pr := &osw.PullResult{}
	pr.Review.Flags = []osw.Flag{
		{Path: "lib", Severity: osw.SeverityInfo},
		{Path: ".mcp.json", Severity: osw.SeverityHigh},
		{Path: ".github/workflows/ci.yml", Severity: osw.SeverityMedium},
	}
	if got := flaggedPaths(pr); strings.Join(got, ",") != ".mcp.json,.github/workflows/ci.yml" {
		t.Errorf("flaggedPaths = %q", got)
	}
}

// GAP-0634: only git's is_ntfs_dotgit forms are left out. A name that
// merely starts with .git (.git.bak, .git.orig, .git.old) is an ordinary
// file or folder: 2b6a5e022e left it out (pattern .git[. ]*), the parent
// pulled it. Controls: .git. , .git.. and git~1 are still left out.
func TestGAP0634GitLikeNamesArePulled(t *testing.T) {
	o, sb, _ := copyInActor(t)
	ctx := context.Background()
	agent := sb.local(remoteProject)
	pulled := map[string]string{".git.bak/config": "[core]\n", ".git.orig": "orig\n", "sub/.git.old/notes.txt": "notes\n"}
	left := []string{".git./hooks/pre-commit", ".git../hooks/pre-commit", "sub/GIT~1/config"}
	for p, c := range pulled {
		write(t, agent, p, c, 0o644)
	}
	for _, p := range left {
		write(t, agent, p, "#!/bin/sh\nid\n", 0o755)
	}
	rv, err := Pull(ctx, PullOptions{Exec: sb, DataDir: o.data, Name: "c1"})
	if err != nil {
		t.Fatalf("the pull failed: %v", err)
	}
	leftOut := ""
	for _, w := range rv.Warnings {
		if strings.Contains(w, "left out, never brought back") {
			leftOut += w + "\n"
		}
	}
	for _, n := range []string{".git.bak", ".git.orig", ".git.old"} {
		if strings.Contains(leftOut, n) {
			t.Errorf("%s is named as left out: %q", n, leftOut)
		}
	}
	for _, p := range []string{".git.", ".git..", "sub/GIT~1"} {
		if !strings.Contains(leftOut, p) {
			t.Errorf("the review does not name %q as left out: %q", p, rv.Warnings)
		}
	}
	if _, err := Apply(ctx, ApplyOptions{DataDir: o.data, Name: "c1", Mode: ModeApply, AcceptSensitive: true}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	for p, c := range pulled {
		if got := read(t, o.project, p); got != c {
			t.Errorf("%s was not brought back: %q", p, got)
		}
	}
	for _, p := range left {
		if _, err := os.Lstat(filepath.Join(o.project, filepath.FromSlash(p))); err == nil {
			t.Errorf("%s was carried into the folder", p)
		}
	}
}
