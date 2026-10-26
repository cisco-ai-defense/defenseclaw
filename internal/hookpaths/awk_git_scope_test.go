// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

func TestR104Refix4AWKVisibleOutput(t *testing.T) {
	skipNativeWindowsHomeGrammar(t)
	home, cwd := r104Loop2Home(t)
	if err := os.WriteFile(filepath.Join(cwd, "read.awk"), []byte("{print}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "writer.awk"), []byte("BEGIN {print \"marker\" >> \"alias\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, command, reason string
	}{
		{"GAP-0498 literal target with dynamic input", `awk 'BEGIN {print "marker" >> "alias"}' "$input"`, "dynamic-argument"},
		{"GAP-0498 literal ordinary target with dynamic input", `awk 'BEGIN {print "marker" >> "report.txt"}' "$input"`, ""},
		{"GAP-0498 protected output after regex", `awk '/x/ {print "marker" > "alias"}' "$input"`, "dynamic-argument"},
		{"GAP-0498 regex data with dynamic input", `awk '/print > "alias"/ {print}' "$input"`, ""},
		{"GAP-0509 expanded target", `out=alias; awk "BEGIN {print \"marker\" >> \"$out\"}"`, "dynamic-argument"},
		{"GAP-0509 expanded target with input", `awk "BEGIN {print \"marker\" >> \"$out\"}" input.txt`, "dynamic-argument"},
		{"GAP-0509 dynamic data can add an output", `awk "BEGIN {print $1 >> \"report.txt\"}" input.txt`, "dynamic-argument"},
		{"GAP-0509 fixed protected output with dynamic data", `awk "BEGIN {print $1 >> \"alias\"}" input.txt`, "dynamic-argument"},
		{"GAP-0509 fixed ordinary output", `awk 'BEGIN {print "marker" >> "report.txt"}' input.txt`, ""},
		{"GAP-0509 no visible file output", `awk "BEGIN {print $field}" input.txt`, ""},
		{"BEN-0482 read-only dynamic AWK", `awk "{print $1}" ~/.ssh/known_hosts > out/known-hostnames.txt`, ""},
		{"GAP-0508 external source writes protected link", `awk -f writer.awk input.txt`, "dynamic-argument"},
		{"GAP-0508 attached program path", `awk -fwriter.awk input.txt`, "dynamic-argument"},
		{"GAP-0508 long program option", `gawk --file=writer.awk input.txt`, "dynamic-argument"},
		{"GAP-0508 unreadable program", `awk -f missing.awk input.txt`, "dynamic-argument"},
		{"GAP-0508 read-only program", `awk -f read.awk input.txt`, ""},
		{"GAP-0508 visible companion output", `gawk -f read.awk -e 'BEGIN {print "marker" >> "alias"}' -- "$input"`, "dynamic-argument"},
	} {
		t.Run(tc.name, func(t *testing.T) { r104Loop2Check(t, tc.command, cwd, home, tc.reason) })
	}
}

func TestR104Refix4GitWorktreeRoot(t *testing.T) {
	home, cwd := r104Loop2Home(t)
	if err := os.Mkdir(filepath.Join(cwd, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(cwd, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, command, target string
		opaque                bool
	}{
		{"GAP-0493 pull can update root", `git -C sub pull && echo marker >> future`, "future", false},
		{"GAP-0493 checkout can update root", `git -C sub checkout -- future && echo marker >> future`, "future", false},
		{"outside repository", `git -C sub pull && echo marker >> ../notes.txt`, "../notes.txt", false},
		{"explicit worktree environment", `GIT_WORK_TREE=.. git -C sub pull && echo marker >> ../notes.txt`, "../notes.txt", false},
		{"explicit worktree config", `git -C sub -c core.worktree=.. pull && echo marker >> ../notes.txt`, "../notes.txt", false},
		{"case-folded worktree config", `git -C sub -c CoRe.WorkTree=.. pull && echo marker >> ../notes.txt`, "../notes.txt", false},
		{"materialization beside protected link", `git -C sub pull && echo marker >> alias`, "alias", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			links := commandLinksWithFacts(tc.command, cwd, home, nil, false)
			target := filepath.Join(cwd, tc.target)
			if got := links.opaqueTarget(target); got != tc.opaque {
				t.Fatalf("opaque target = %v, want %v", got, tc.opaque)
			}
		})
	}
}

func TestR104Refix4GitWorktreeMarker(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	args := []string{"-C", "sub", "pull"}
	static := []bool{true, true, true}
	if scope, materializes := gitMaterializationScope(args, static, root); !materializes || scope != "" {
		t.Fatalf("unknown repository scope = %q, materializes = %v", scope, materializes)
	}
	if err := os.WriteFile(filepath.Join(root, ".git"), []byte("gitdir: elsewhere\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if scope, materializes := gitMaterializationScope(args, static, root); !materializes || scope != root {
		t.Fatalf("worktree-file scope = %q, materializes = %v, want %q", scope, materializes, root)
	}
	alias := filepath.Join(t.TempDir(), "repo")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	if scope, materializes := gitMaterializationScope(
		[]string{"-C", "repo/sub", "pull"}, []bool{true, true, true}, filepath.Dir(alias),
	); !materializes || scope != root {
		t.Fatalf("physical worktree scope = %q, materializes = %v, want %q", scope, materializes, root)
	}
}
