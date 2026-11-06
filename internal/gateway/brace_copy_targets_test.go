// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// TestBraceBackupCopyInProjectIsAllowed: a cp operand spelled as a brace
// expansion of plain text is the fixed words bash makes of it. A backup copy
// of a project file to a brace-expanded name in the project writes only that
// project file, so action mode allows it per-user as on managed, for Claude
// Code and Codex (rel-1-0-6 GAP-0202). A brace copy whose real destination
// is the keys file, or the project link to it, keeps blocking on both.
func TestBraceBackupCopyInProjectIsAllowed(t *testing.T) {
	r106Reader2Check(t, []r106Reader2Row{
		{"three operands, brace backup", "project", `cp README.md README.md{,.bak}`, "allow"},
		{"three operands, other suffix", "project", `cp a.txt a.txt{,.orig}`, "allow"},
		{"backup idiom", "project", `cp README.md{,.bak}`, "allow"},
		{"backup idiom then read", "project", `cp a.txt{,.orig} && cat a.txt.orig`, "allow"},
		{"two sources into a project dir", "project", `cp {a.txt,README.md} ordinary/`, "allow"},
		{"absolute backup", "project", `cp {P}/a.txt {P}/a.txt{,.orig}`, "allow"},
		{"many sources into a project dir", "project", `cp a.txt{1..300} ordinary/`, "allow"},
		// rel-1-0-6:GAP-0675 (owner 2026-11-06): the default profile alerts on a shell-command protected-file write; strict blocks it (TestGAP0675ShellProtectedFileWarnsOutsideStrictOnEveryRoute).
		{"keys file by brace", "project", `cp {README.md,{K}}`, "alert"},
		{"keys file by relative brace", "project", `cp {README.md,../.ssh/authorized_keys}`, "alert"},
	})
}

// TestBraceCopyOntoKeysLinkBlocks: a brace copy whose real destination is
// the project link to the keys file writes the keys file; a managed gateway
// blocks it from the hook client reading of the expanded destination, as a
// per-user gateway does (rel-1-0-6 GAP-0205). A copy past the brace budget
// takes the evaluation limit on both before any reader expands it
// (GAP-0187).
func TestBraceCopyOntoKeysLinkBlocks(t *testing.T) {
	r106Reader2Check(t, []r106Reader2Row{
		// rel-1-0-6:GAP-0675 (owner 2026-11-06): the default profile alerts on a shell-command protected-file write; strict blocks it (TestGAP0675ShellProtectedFileWarnsOutsideStrictOnEveryRoute).
		{"link by brace", "project", `cp {README.md,keylink}`, "alert"},
		{"link by backup idiom", "project", `echo x > key && cp key{,link}`, "alert"},
		{"link by absolute brace", "project", `cp {P}/{README.md,keylink}`, "alert"},
		{"past the brace budget", "project", `cp a.txt{1..70000} ordinary/`, "block"},
	})
}
