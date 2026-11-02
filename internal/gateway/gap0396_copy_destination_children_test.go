// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestGAP0396CopyDestinationChildrenFourCell is rel-1-0-6:GAP-0396 and its
// review variants (plans/r107/IN-p5-reader-REVIEW-1..3). A plain cp writes
// DEST itself, or DEST/NAME for each source NAME when DEST is a directory,
// through an existing link at that name. Each protected row has a link to
// the keys file at the written name; each benign twin has the same sources
// with no link, or a link at a name the sources cannot produce. A source
// pattern past the reader's bounds keeps the destination's link children
// that the pattern may name.
func TestGAP0396CopyDestinationChildrenFourCell(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	many := make([]string, 0, 40)
	for i := 0; i < 40; i++ {
		many = append(many, fmt.Sprintf("a%02d.md", i))
	}
	rows := []struct {
		name, command, link, want string
		sources                   []string
	}{
		{"one-match-adjacent-ext", `cp *.md build/`, "", "allow", []string{"a.md", "report.txt"}},
		{"one-match-adjacent-ext-dest-link", `cp *.md keylink`, "", "block", []string{"a.md", "report.txt"}},
		{"cfg-dest-link", `cp *.cfg keylink`, "", "block", []string{"a.cfg"}},
		{"qmark-dest-link", `cp ?.md keylink`, "", "block", []string{"a.md"}},
		{"bracket-dest-link", `cp [a].md keylink`, "", "block", []string{"a.md"}},
		{"subdir-dest-link", `cp src/*.md keylink`, "", "block", []string{"src/s.md"}},
		{"glob-to-file-dest", `cp *.md notes.txt`, "", "allow", []string{"a.md", "notes.txt"}},
		{"literal-to-file-dest", `cp a.md b.md`, "", "allow", []string{"a.md", "b.md"}},
		{"literal-to-new-name", `cp a.md fresh.md`, "", "allow", []string{"a.md"}},
		{"simple-ordinary", `cp a*.md build/`, "", "allow", []string{"a1.md", "a2.md"}},
		{"simple-linked", `cp a*.md build/`, "a1.md", "block", []string{"a1.md", "a2.md"}},
		{"bracket-ordinary", `cp a[12].md build/`, "", "allow", []string{"a1.md", "a2.md"}},
		{"bracket-linked", `cp a[12].md build/`, "a1.md", "block", []string{"a1.md", "a2.md"}},
		{"subdir-ordinary", `cp src/*.md build/`, "", "allow", []string{"src/s.md"}},
		{"subdir-linked", `cp src/*.md build/`, "s.md", "block", []string{"src/s.md"}},
		{"nested-ordinary", `cp src/*/*.md build/`, "", "allow", []string{"src/nested/s.md"}},
		{"nested-linked", `cp src/*/*.md build/`, "s.md", "block", []string{"src/nested/s.md"}},
		{"nested-disjoint-link", `cp src/*/*.md build/`, "a.md", "allow", []string{"src/nested/s.md"}},
		{"negated-bracket-linked", `cp a[!2].md build/`, "a1.md", "block", []string{"a1.md", "a2.md"}},
		{"negated-bracket-disjoint", `cp a[!2].md build/`, "a2.md", "allow", []string{"a1.md", "a2.md"}},
		{"posix-class-linked", `cp a[[:digit:]].md build/`, "a1.md", "block", []string{"a1.md"}},
		{"posix-class-disjoint", `cp a[[:digit:]].md build/`, "notes.md", "allow", []string{"a1.md"}},
		{"literal-linked", `cp src/s.md build/`, "s.md", "block", []string{"src/s.md"}},
		{"literal-disjoint", `cp src/s.md build/`, "a.md", "allow", []string{"src/s.md"}},
		{"dot-source-linked", `cp ./src/s.md build/`, "s.md", "block", []string{"src/s.md"}},
		{"dot-source-ordinary", `cp ./src/s.md build/`, "", "allow", []string{"src/s.md"}},
		{"dot-glob-linked", `cp ./src/*.md build/`, "s.md", "block", []string{"src/s.md"}},
		{"dot-glob-ordinary", `cp ./src/*.md build/`, "", "allow", []string{"src/s.md"}},
		{"parent-source-linked", `cp src/../a1.md build/`, "a1.md", "block", []string{"a1.md", "src/x"}},
		{"parent-source-ordinary", `cp src/../a1.md build/`, "", "allow", []string{"a1.md", "src/x"}},
		{"brace-source-linked", `cp src/{nested,other}/s.md build/`, "s.md", "block", []string{"src/nested/s.md", "src/other/s.md"}},
		{"brace-source-ordinary", `cp src/{nested,other}/s.md build/`, "", "allow", []string{"src/nested/s.md", "src/other/s.md"}},
		{"brace-simple-linked", `cp {a1,a2}.md build/`, "a1.md", "block", []string{"a1.md", "a2.md"}},
		{"brace-simple-ordinary", `cp {a1,a2}.md build/`, "", "allow", []string{"a1.md", "a2.md"}},
		{"absent-source", `cp src/*.pdf build/`, "s.pdf", "allow", []string{"src/s.md"}},
		{"past-bound-linked", `cp a*.md build/`, "a07.md", "block", many},
		{"past-bound-ordinary", `cp a*.md build/`, "", "allow", many},
		{"past-bound-disjoint-link", `cp a*.md build/`, "notes.txt", "allow", many},
	}
	var calls []*hookCall
	for _, row := range rows {
		project := filepath.Join(f.home, "gap0396-"+row.name)
		if err := os.MkdirAll(filepath.Join(project, "build"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(f.keys, filepath.Join(project, "keylink")); err != nil {
			t.Fatal(err)
		}
		for _, source := range row.sources {
			path := filepath.Join(project, source)
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("source\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if row.link != "" {
			if err := os.Symlink(f.keys, filepath.Join(project, "build", row.link)); err != nil {
				t.Fatal(err)
			}
		}
		payload := mustJSON(t, map[string]any{"session_id": "gap0396", "hook_event_name": "PreToolUse", "cwd": project,
			"permission_mode": "default", "tool_name": "Bash", "tool_use_id": "toolu_gap0396",
			"tool_input": map[string]any{"command": row.command}})
		calls = append(calls, everyMode(row.name, payload, f.clientHeader(t, payload))...)
	}
	f.answerAll(t, calls)
	for i, call := range calls {
		want := rows[i/4].want
		t.Logf("R0396 row=%s cell=%s got=%s want=%s", rows[i/4].name, call.name, call.verdict, want)
		if call.verdict != want {
			t.Errorf("%s: verdict %s, want %s; body %.200s", call.name, call.verdict, want, call.body)
		}
	}
}
