// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"strings"
	"testing"
)

// GAP-2275: the literal writer reader lists an mv, install or rsync
// destination only below a process link (GAP-2227, GAP-2237). A plain
// rename or folder sync keeps its own readers (the rename, the move onto a
// link, the recursive copy scope); listing it as a literal write judged
// rsync -aH src/ dst/ and mv onto a link as key-file writes.
func TestGAP2275MoveInstallSyncLiteralWritesOnlyBelowProcessLinks(t *testing.T) {
	cwd, home := t.TempDir(), t.TempDir()
	rows := []struct {
		command string
		link    bool
	}{
		{"rsync -aH src/ dst/", false},
		{"rsync -a --link-dest=../prev src/ cur/", false},
		{"mv a.txt b.txt", false},
		{"mv -b a.txt alias", false},
		{"mv -t out a.txt", false},
		{"install -m 644 a b", false},
		{"install -t out a.txt", false},
		{"mv a.txt /proc/self/cwd/../notes.txt", true},
		{"mv -t /proc/self/cwd/../out a.txt", true},
		{"install -m 644 a /proc/self/cwd/../out/a", true},
		{"install -t /proc/self/cwd/../out a.txt", true},
		{"rsync -a src/ /proc/self/cwd/../backup/", true},
	}
	for _, row := range rows {
		got := LiteralWriteOperands(row.command, cwd, home)
		if !row.link {
			if len(got) != 0 {
				t.Errorf("%q: literal writes %q, want none (its own readers judge it)", row.command, got)
			}
			continue
		}
		if len(got) != 1 || !strings.HasPrefix(got[0], "/proc/self/cwd/") {
			t.Errorf("%q: literal writes %q, want the process-link destination", row.command, got)
		}
	}
}

// GAP-2274: a copy destination that is not below a process link is cleaned,
// as at rel, so the hook config guard matches x/../.claude/settings.json to
// the registered file. Only a process-link destination keeps its dot-dot.
func TestGAP2274CopyDestinationDotDotIsCleanedOutsideProcessLinks(t *testing.T) {
	cwd, home := t.TempDir(), t.TempDir()
	want := home + "/.claude/settings.json"
	for _, command := range []string{
		"cp new.json " + home + "/proj/../.claude/settings.json",
		"cp -f new.json " + home + "/a/b/../../.claude/settings.json",
	} {
		got := LiteralWriteOperands(command, cwd, home)
		if len(got) != 1 || got[0] != want {
			t.Errorf("%q: literal writes %q, want [%s]", command, got, want)
		}
	}
}
