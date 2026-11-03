// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// A Bash punctuation glob copies the punctuation source. Mark sources in the
// same folder distinguish shell punctuation from marks that are alphabetic to
// the shell, even when a destination entry points at a protected file.
func TestReviewR0396R3UnicodeMarkTwins(t *testing.T) {
	t.Setenv("LC_ALL", "C.utf8")
	f := newB36ManagedHookFixture(t)
	rows := []struct {
		name, marked, link, want string
		hard                     bool
	}{
		{"devanagari-spacing-mark-symlink", "a\u093e.md", "a\u093e.md", "allow", false},
		{"bengali-spacing-mark-hardlink", "a\u09be.md", "a\u09be.md", "allow", true},
		{"gujarati-spacing-mark-symlink", "a\u0abe.md", "a\u0abe.md", "allow", false},
		{"hebrew-nonspacing-mark-symlink", "a\u05b0.md", "a\u05b0.md", "allow", false},
		{"true-punctuation-protected-symlink", "a\u00b7.md", "a\u00b7.md", "block", false},
		{"true-punctuation-protected-hardlink", "a\u00b7.md", "a\u00b7.md", "block", true},
		{"tibetan-spacing-mark-protected", "a\u0f3e.md", "a\u0f3e.md", "block", false},
		{"combining-accent-protected", "a\u0301.md", "a\u0301.md", "block", false},
		{"unicode-letter-disjoint-symlink", "a\u00e9.md", "a\u00e9.md", "allow", false},
	}
	for _, r := range rows {
		project := filepath.Join(f.home, "r0396-r3-"+r.name)
		build := filepath.Join(project, "build")
		if err := os.MkdirAll(build, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"a\u00b7.md", r.marked} {
			if err := os.WriteFile(filepath.Join(project, name), []byte("safe\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		dest := filepath.Join(build, r.link)
		var err error
		if r.hard {
			err = os.Link(f.keys, dest)
		} else {
			err = os.Symlink(f.keys, dest)
		}
		if err != nil {
			t.Fatal(err)
		}
		payload := mustJSON(t, map[string]any{"session_id": "r0396-r3", "hook_event_name": "PreToolUse", "cwd": project, "permission_mode": "default", "tool_name": "Bash", "tool_use_id": "toolu_r0396_r3", "tool_input": map[string]any{"command": "cp a[[:punct:]].md build/"}})
		calls := everyMode(r.name, payload, f.clientHeader(t, payload))
		f.answerAll(t, calls)
		for _, call := range calls {
			t.Logf("R0396R3 row=%s cell=%s got=%s want=%s", r.name, call.name, call.verdict, r.want)
			if call.verdict != r.want {
				t.Errorf("%s: got=%s want=%s", call.name, call.verdict, r.want)
			}
		}
	}
}
