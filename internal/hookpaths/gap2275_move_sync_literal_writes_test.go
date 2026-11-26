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

func TestGAP2275ThroughProcessLink(t *testing.T) {
	rows := []struct {
		path string
		want bool
	}{
		{"/proc/self/cwd/../x", true},
		{"/proc/4242/root/tmp/x", true},
		{"/proc/self/task/42/cwd/x", true},
		{"/dev/fd/3/x", true},
		{"/dev/stdout", true},
		{"//proc/./self/cwd", true},
		{"/home/u/proc/self/cwd/x", false},
		{"/proc/self/status", false},
		{"/tmp/dst", false},
		{"dst/", false},
	}
	for _, row := range rows {
		if got := throughProcessLink(row.path); got != row.want {
			t.Errorf("throughProcessLink(%q) = %t, want %t", row.path, got, row.want)
		}
	}
	if got := processLinkWrites([]string{"/srv/out/a"}, "/proc/self/cwd"); len(got) != 1 {
		t.Errorf("a call placed below a process link keeps its operands, got %q", got)
	}
}
