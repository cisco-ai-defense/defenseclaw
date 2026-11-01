// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// GAP-1388: a session's snapshot of a directory is keyed by the directory,
// not by the spelling that reached it: a directory reached through a
// symlinked spelling (macOS /var is /private/var) is recorded under its
// physical name too, so a later write through either spelling to the
// AGENTS.md that was there blocks in action mode, and an AGENTS.md the
// session creates there stays its own.
func TestR105GAP1388SnapshotKeyedByTheDirectoryNotItsSpelling(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX symlinks")
	}
	home := instructionIdentityTestRoot(t)
	restore, err := connector.BindUserHomeDir(home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restore)
	first := filepath.Join(home, "first")
	if err := os.MkdirAll(first, 0o700); err != nil {
		t.Fatal(err)
	}
	physical := filepath.Join(home, "private", "second")
	existing := writeActiveAgentTestFile(t, physical, "AGENTS.md")
	linked := filepath.Join(home, "second")
	if err := os.Symlink(physical, linked); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	// block_at HIGH isolates the spelling from the default-level change
	// of GAP-1503.
	route := newR105CodexRoute(t, home, "HIGH")
	route.start("live", first)
	// The session reaches the second workdir through the linked spelling:
	// its AGENTS.md was there first and stays protected under both names.
	if action, findings := route.bash("live", linked, "ls"); action == guardrailActionBlock {
		t.Fatalf("ls in the linked workdir blocked: %v", findings)
	}
	for _, cwd := range []string{linked, physical} {
		if action, findings := route.bash("live", cwd, "printf x >> AGENTS.md"); action != guardrailActionBlock || !findingStringHasRuleID(findings, "COG-AGENTS-MD") {
			t.Fatalf("pre-existing AGENTS.md from %s: action=%q findings=%v, want block COG-AGENTS-MD", cwd, action, findings)
		}
	}
	_ = existing
	// A workdir reached empty through its linked spelling: the AGENTS.md
	// the session creates there is its own under both names.
	created := filepath.Join(home, "private", "third")
	if err := os.MkdirAll(created, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(home, "third")
	if err := os.Symlink(created, link); err != nil {
		t.Fatal(err)
	}
	if action, findings := route.bash("live", link, "ls"); action == guardrailActionBlock {
		t.Fatalf("ls in the linked empty workdir blocked: %v", findings)
	}
	writeActiveAgentTestFile(t, created, "AGENTS.md")
	for _, cwd := range []string{created, link} {
		if action, findings := route.bash("live", cwd, "printf x >> AGENTS.md"); action == guardrailActionBlock || findingStringHasRuleID(findings, "COG-AGENTS-MD") {
			t.Fatalf("own created AGENTS.md from %s: action=%q findings=%v", cwd, action, findings)
		}
	}
}
