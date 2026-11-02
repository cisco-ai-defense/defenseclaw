// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestGAP0396Review1IndependentCopyCells(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	type row struct {
		name, command, link, want          string
		sources                            []string
		hard, destDirLink                  bool
		sourceCount, destCount, sourceDirs int
	}
	rows := []row{
		{name: "adjacent-md-link", command: `cp a*.md build/`, link: "a1.md", want: "block", sources: []string{"a1.md", "a2.txt"}},
		{name: "adjacent-md-disjoint", command: `cp a*.md build/`, link: "a2.txt", want: "allow", sources: []string{"a1.md", "a2.txt"}},
		{name: "nested-bracket-link", command: `cp src/[ab]/*.cfg build/`, link: "key.cfg", want: "block", sources: []string{"src/a/key.cfg", "src/b/other.cfg"}},
		{name: "nested-bracket-disjoint", command: `cp src/[ab]/*.cfg build/`, link: "unused.cfg", want: "allow", sources: []string{"src/a/key.cfg", "src/b/other.cfg"}},
		{name: "brace-pattern-link", command: `cp src/{a,b}/*.cfg build/`, link: "key.cfg", want: "block", sources: []string{"src/a/key.cfg", "src/b/other.cfg"}},
		{name: "negated-uppercase-lower-source", command: `cp [!A].md build/`, link: "a.md", want: "block", sources: []string{"a.md"}},
		{name: "negated-lowercase-upper-source", command: `cp [!a].md build/`, link: "A.md", want: "block", sources: []string{"A.md"}},
		{name: "negated-posix-upper-lower-source", command: `cp [![:upper:]].md build/`, link: "a.md", want: "block", sources: []string{"a.md"}},
		{name: "negated-uppercase-disjoint", command: `cp [!A].md build/`, link: "A.md", want: "allow", sources: []string{"a.md"}},
		{name: "negated-lowercase-disjoint", command: `cp [!a].md build/`, link: "a.md", want: "allow", sources: []string{"A.md"}},
		{name: "negated-posix-upper-disjoint", command: `cp [![:upper:]].md build/`, link: "A.md", want: "allow", sources: []string{"a.md"}},
		{name: "unsupported-class-protected", command: `cp a[[:punct:]].md build/`, link: "a-.md", want: "block", sources: []string{"a-.md"}},
		{name: "unsupported-class-disjoint", command: `cp a[[:punct:]].md build/`, link: "notes.txt", want: "allow", sources: []string{"a-.md"}},
		{name: "unsupported-class-same-width-disjoint", command: `cp a[[:punct:]].md build/`, link: "ab.md", want: "allow", sources: []string{"a-.md"}},
		{name: "unsupported-class-hardlink", command: `cp a[[:punct:]].md build/`, link: "a-.md", want: "block", sources: []string{"a-.md"}, hard: true},
		{name: "unsupported-class-hardlink-disjoint", command: `cp a[[:punct:]].md build/`, link: "notes.txt", want: "allow", sources: []string{"a-.md"}, hard: true},
		{name: "mixed-fixed-pattern-link", command: `cp fixed.txt src/a/*.cfg build/`, link: "fixed.txt", want: "block", sources: []string{"fixed.txt", "src/a/key.cfg"}},
		{name: "dot-parent-link", command: `cp ./src/../a1.md build/`, link: "a1.md", want: "block", sources: []string{"src/keep", "a1.md"}},
		{name: "directory-destination-link", command: `cp a*.md dlink`, link: "a1.md", want: "block", sources: []string{"a1.md"}, destDirLink: true},
		{name: "file-destination-disjoint", command: `cp a*.md notes.txt`, link: "a1.md", want: "allow", sources: []string{"a1.md", "notes.txt"}},
		{name: "overflow-source-symlink", command: `cp a*.md build/`, link: "a07.md", want: "block", sourceCount: 40},
		{name: "overflow-source-hardlink", command: `cp a*.md build/`, link: "a07.md", want: "block", sourceCount: 40, hard: true},
		{name: "overflow-source-hardlink-disjoint", command: `cp a*.md build/`, link: "unused.txt", want: "allow", sourceCount: 40, hard: true},
		{name: "overflow-source-disjoint", command: `cp a*.md build/`, link: "unused.txt", want: "allow", sourceCount: 40},
		{name: "overflow-destination-symlink", command: `cp a*.md build/`, link: "a1.md", want: "block", sources: []string{"a1.md"}, destCount: 4100},
		{name: "overflow-destination-hardlink", command: `cp a*.md build/`, link: "a1.md", want: "block", sources: []string{"a1.md"}, destCount: 4100, hard: true},
		{name: "overflow-destination-disjoint", command: `cp a*.md build/`, link: "unused.txt", want: "allow", sources: []string{"a1.md"}, destCount: 4100},
		{name: "both-bounds-symlink", command: `cp a*.md build/`, link: "a07.md", want: "block", sourceCount: 40, destCount: 4100},
		{name: "both-bounds-hardlink", command: `cp a*.md build/`, link: "a07.md", want: "block", sourceCount: 40, destCount: 4100, hard: true},
		{name: "both-bounds-hardlink-disjoint", command: `cp a*.md build/`, link: "unused.txt", want: "allow", sourceCount: 40, destCount: 4100, hard: true},
		{name: "both-bounds-disjoint", command: `cp a*.md build/`, link: "unused.txt", want: "allow", sourceCount: 40, destCount: 4100},
		{name: "read-bound-symlink", command: `cp src/*/*.md build/`, link: "a07.md", want: "block", sourceDirs: 18},
		{name: "read-bound-hardlink", command: `cp src/*/*.md build/`, link: "a07.md", want: "block", sourceDirs: 18, hard: true},
		{name: "read-bound-disjoint", command: `cp src/*/*.md build/`, link: "unused.txt", want: "allow", sourceDirs: 18},
		{name: "read-bound-hardlink-disjoint", command: `cp src/*/*.md build/`, link: "unused.txt", want: "allow", sourceDirs: 18, hard: true},
		{name: "unproved-both-bounds", command: `cp src/*/*.md build/`, link: "a07.md", want: "block", sourceDirs: 18, destCount: 4100},
		{name: "unproved-both-bounds-hardlink", command: `cp src/*/*.md build/`, link: "a07.md", want: "block", sourceDirs: 18, destCount: 4100, hard: true},
	}
	for _, r := range rows {
		project := filepath.Join(f.home, "r0396-independent-"+r.name)
		build := filepath.Join(project, "build")
		if err := os.MkdirAll(build, 0700); err != nil {
			t.Fatal(err)
		}
		for _, source := range r.sources {
			p := filepath.Join(project, source)
			if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte("source\n"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		for i := 0; i < r.sourceCount; i++ {
			p := filepath.Join(project, fmt.Sprintf("a%02d.md", i))
			if err := os.WriteFile(p, []byte("source\n"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		for i := 0; i < r.sourceDirs; i++ {
			p := filepath.Join(project, "src", fmt.Sprintf("d%02d", i), fmt.Sprintf("a%02d.md", i))
			if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte("source\n"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		for i := 0; i < r.destCount; i++ {
			p := filepath.Join(build, fmt.Sprintf("ordinary-%04d.txt", i))
			if err := os.WriteFile(p, []byte("ordinary\n"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		if r.link != "" {
			p := filepath.Join(build, r.link)
			var err error
			if r.hard {
				err = os.Link(f.keys, p)
			} else {
				err = os.Symlink(f.keys, p)
			}
			if err != nil {
				t.Fatal(err)
			}
		}
		if r.destDirLink {
			if err := os.Symlink(build, filepath.Join(project, "dlink")); err != nil {
				t.Fatal(err)
			}
		}
		payload := mustJSON(t, map[string]any{"session_id": "r0396-independent", "hook_event_name": "PreToolUse", "cwd": project, "permission_mode": "default", "tool_name": "Bash", "tool_use_id": "toolu_r0396", "tool_input": map[string]any{"command": r.command}})
		calls := everyMode(r.name, payload, f.clientHeader(t, payload))
		f.answerAll(t, calls)
		for _, call := range calls {
			t.Logf("R0396MUT row=%s cell=%s got=%s want=%s", r.name, call.name, call.verdict, r.want)
			if call.verdict != r.want {
				t.Errorf("%s: got=%s want=%s", call.name, call.verdict, r.want)
			}
		}
	}
}
