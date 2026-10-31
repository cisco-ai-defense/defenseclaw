// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// TestReadOfLinkReplacedByMoveIsAllowed: a plain mv onto an existing link to
// the keys file replaces the link entry with the moved file, so a read-only
// call on that name later in the same command (ls -l, stat, cat) reads the
// moved file. Action mode allows it per-user as on managed, for Claude Code
// and Codex (rel-1-0-6:GAP-0217). A write that still reaches the keys file,
// a move into the keys path and a read of a link no move replaced keep
// their verdicts.
func TestReadOfLinkReplacedByMoveIsAllowed(t *testing.T) {
	r106Reader2Check(t, []r106Reader2Row{
		{"mv then ls", "project", `mv a.txt keylink && ls -l keylink`, "allow"},
		{"mv then stat", "project", `mv a.txt keylink; stat keylink`, "allow"},
		{"mv then cat", "project", `mv a.txt keylink && cat keylink`, "allow"},
		{"mv -f then wc", "project", `mv -f a.txt keylink && wc -c keylink`, "allow"},
		{"absolute mv then ls", "project", `mv a.txt {P}/keylink && ls -l {P}/keylink`, "allow"},
		{"tilde mv then ls", "project", `mv a.txt ~/project/keylink && ls -l ~/project/keylink`, "allow"},
		{"from home, mv then ls", "home", `mv project/a.txt project/keylink && ls -l project/keylink`, "allow"},
		{"mv alone", "project", `mv a.txt keylink`, "allow"},
		{"keys write after the move", "project", `mv a.txt keylink && echo k >> ../.ssh/authorized_keys`, "block"},
		{"read then write through an unmoved link", "project", `mv a.txt b.txt && ls -l keylink && echo k >> keylink`, "block"},
		{"read redirected into the keys file", "project", `mv a.txt keylink && cat keylink > ../.ssh/authorized_keys`, "block"},
		{"move into the keys path then ls", "project", `mv a.txt ../.ssh/authorized_keys && ls -l ../.ssh/authorized_keys`, "block"},
		{"link made again then written", "project", `mv a.txt keylink && ln -sfn ../.ssh/authorized_keys keylink && echo k >> keylink`, "block"},
	})
}
