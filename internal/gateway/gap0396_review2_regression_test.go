// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestReviewR0396Round2Bounds(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	type row struct {
		name, command, link, want, locale, destSuffix string
		sourceDirs, sourceCount, destCount, safeLinks int
		sources                                       []string
		hard                                          bool
	}
	rows := []row{
		{name: "unproved-both-bounds-no-link", command: "cp src/*/*.md build/", want: "allow", sourceDirs: 18, destCount: 4100},
		{name: "unproved-both-bounds-disjoint-link", command: "cp src/*/*.md build/", link: "unused.txt", want: "allow", sourceDirs: 18, destCount: 4100},
		{name: "unproved-both-bounds-protected-link", command: "cp src/*/*.md build/", link: "a07.md", want: "block", sourceDirs: 18, destCount: 4100},
		{name: "unproved-both-bounds-protected-hardlink", command: "cp src/*/*.md build/", link: "a07.md", want: "block", sourceDirs: 18, destCount: 4100, hard: true},
		{name: "unproved-both-bounds-late-symlink", command: "cp src/*/*.md build/", link: "z99.md", want: "block", sourceDirs: 18, destCount: 4100, sources: []string{"src/d17/z99.md"}},
		{name: "unproved-both-bounds-late-hardlink", command: "cp src/*/*.md build/", link: "z99.md", want: "block", sourceDirs: 18, destCount: 4100, sources: []string{"src/d17/z99.md"}, hard: true},
		{name: "unproved-both-bounds-late-disjoint", command: "cp src/*/*.md build/", link: "z99.md", want: "allow", sourceDirs: 18, destCount: 4100, sources: []string{"src/d17/other.txt"}},
		{name: "unproved-matching-ordinary-no-link", command: "cp src/*/*.md build/", want: "allow", sourceDirs: 18, destCount: 4100, destSuffix: ".md"},
		{name: "unproved-matching-ordinary-late-link", command: "cp src/*/*.md build/", link: "z99.md", want: "block", sourceDirs: 18, destCount: 4100, destSuffix: ".md", sources: []string{"src/d17/z99.md"}},
		{name: "over-fact-bound-safe-links", command: "cp a*.md build/", want: "allow", sourceCount: 40, safeLinks: 33},
		{name: "over-fact-bound-protected-link", command: "cp a*.md build/", link: "a39.md", want: "block", sourceCount: 40, safeLinks: 33},
		{name: "over-fact-bound-protected-hardlink", command: "cp a*.md build/", link: "a39.md", want: "block", sourceCount: 40, safeLinks: 33, hard: true},
		{name: "unicode-punct-protected-link", command: "cp a[[:punct:]].md build/", link: "a·.md", want: "block", sources: []string{"a·.md"}},
		{name: "unicode-punct-protected-hardlink", command: "cp a[[:punct:]].md build/", link: "a—.md", want: "block", sources: []string{"a—.md"}, hard: true},
		{name: "unicode-punct-number-protected", command: "cp a[[:punct:]].md build/", link: "a¼.md", want: "block", sources: []string{"a¼.md"}},
		{name: "unicode-punct-private-protected", command: "cp a[[:punct:]].md build/", link: "a\uE000.md", want: "block", sources: []string{"a\uE000.md"}, hard: true},
		{name: "unicode-punct-disjoint-link", command: "cp a[[:punct:]].md build/", link: "notes.txt", want: "allow", sources: []string{"a·.md"}},
		{name: "unicode-punct-letter-disjoint", command: "cp a[[:punct:]].md build/", link: "aé.md", want: "allow", sources: []string{"a·.md"}},
		{name: "unicode-punct-number-disjoint", command: "cp a[[:punct:]].md build/", link: "a¼.md", want: "allow", sources: []string{"a·.md"}},
		{name: "c-locale-unicode-disjoint", command: "cp a[[:punct:]].md build/", link: "a·.md", want: "allow", sources: []string{"a·.md"}, locale: "C"},
		{name: "c-locale-ascii-protected", command: "cp a[[:punct:]].md build/", link: "a-.md", want: "block", sources: []string{"a-.md"}, locale: "C"},
	}
	for _, r := range rows {
		if r.locale != "" {
			t.Setenv("LC_ALL", r.locale)
		}
		project := filepath.Join(f.home, "r0396-r2-"+r.name)
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
		for i := 0; i < r.sourceDirs; i++ {
			p := filepath.Join(project, "src", fmt.Sprintf("d%02d", i), fmt.Sprintf("a%02d.md", i))
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
		for i := 0; i < r.destCount; i++ {
			suffix := r.destSuffix
			if suffix == "" {
				suffix = ".txt"
			}
			p := filepath.Join(build, fmt.Sprintf("ordinary-%04d%s", i, suffix))
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
		if r.safeLinks != 0 {
			safe := filepath.Join(project, "safe.txt")
			if err := os.WriteFile(safe, []byte("safe\n"), 0600); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < r.safeLinks; i++ {
				if err := os.Symlink(safe, filepath.Join(build, fmt.Sprintf("a%02d.md", i))); err != nil {
					t.Fatal(err)
				}
			}
		}
		payload := mustJSON(t, map[string]any{"session_id": "r0396-r2", "hook_event_name": "PreToolUse", "cwd": project, "permission_mode": "default", "tool_name": "Bash", "tool_use_id": "toolu_r0396_r2", "tool_input": map[string]any{"command": r.command}})
		calls := everyMode(r.name, payload, f.clientHeader(t, payload))
		f.answerAll(t, calls)
		for _, call := range calls {
			t.Logf("R0396R2 row=%s cell=%s got=%s want=%s", r.name, call.name, call.verdict, r.want)
			if call.verdict != r.want {
				t.Errorf("%s: got=%s want=%s", call.name, call.verdict, r.want)
			}
		}
	}
}
