// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package workspace

import (
	"strings"
	"testing"

	osw "github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

// GAP-0101: a file the agent names "x\nOther changes:\n  README.md" cannot
// forge review lines; it is shown quoted, with its newlines as \n.
func TestReviewQuotesTheAgentsPaths(t *testing.T) {
	r := &Review{
		Summary: "2 files changed (+3 -0)\nOther changes:",
		Flagged: 1,
		Changed: []File{
			{Path: ".envrc", Status: "added", Flags: []string{"can run code on this computer"}},
			{Path: "x\nOther changes:\n  README.md", Status: "added"},
			{Path: "ok\x1b[2A\x1b[2Kall clear\r", Status: "modified"},
		},
		Dropped:  []string{"secret\nrefused: nothing"},
		Blocking: []string{"a\nb"},
		Warnings: []string{"c\rd\x1b]52;c;AAAA\x07"},
	}
	text := r.render("web-1\nweb-2")
	n := 0
	for _, l := range strings.Split(text, "\n") {
		if l == "Other changes:" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d \"Other changes:\" lines, want the launcher's one: %q", n, text)
	}
	if strings.ContainsAny(text, "\r\x1b\x07") {
		t.Errorf("review keeps a terminal control: %q", text)
	}
	if !strings.Contains(text, `"x\nOther changes:\n  README.md"`) {
		t.Errorf("the forged path is not shown quoted: %q", text)
	}
	if got := strings.Count(text, "\n"); got != 9 {
		t.Errorf("%d lines, want 9: %q", got, text)
	}
}

func TestActorErrorTextIsOneLine(t *testing.T) {
	err := failure("the restore point", &osw.ExecResult{ExitCode: 1, Stderr: []byte("first\nbad\x1b[2J thing\rall fine")})
	if strings.ContainsAny(err.Error(), "\r\x1b\n") {
		t.Errorf("actor stderr reaches the terminal as it is: %q", err)
	}
}
