// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

func resolvedEvidence(t *testing.T, connector, cwd, tool string, input map[string]interface{}) map[string]string {
	t.Helper()
	body, err := json.Marshal(map[string]interface{}{
		"hook_event_name": "PreToolUse", "session_id": "s", "cwd": cwd, "tool_name": tool, "tool_input": input,
	})
	if err != nil {
		t.Fatal(err)
	}
	targets, ok := Decode(ResolveConnector(connector, "", "PreToolUse", body))
	if !ok {
		t.Fatalf("no evidence for %s", tool)
	}
	return targets
}

// GAP-1127: a write to one file with two instruction names (CLAUDE.md and
// SOUL.md hard-linked) names both in the client's identity evidence.
func TestResolveNamesEveryInstructionNameOfTheFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX hard links")
	}
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	claude := filepath.Join(project, "CLAUDE.md")
	if err := os.WriteFile(claude, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	soul, third := filepath.Join(project, "SOUL.md"), filepath.Join(project, "notes.txt")
	for _, link := range []string{soul, third} {
		if err := os.Link(claude, link); err != nil {
			t.Skipf("hard links unavailable: %v", err)
		}
	}
	targets := resolvedEvidence(t, "claudecode", project, "Bash", map[string]interface{}{"command": "printf x >> notes.txt"})
	named := InstructionIdentities(targets)
	if !slices.Contains(named, claude) || !slices.Contains(named, soul) {
		t.Fatalf("identity evidence %q names not every instruction name of the file", named)
	}
	if got := NewInstructionFiles(project, "", nil).Aliases(third); !slices.Contains(got, claude) || !slices.Contains(got, soul) {
		t.Fatalf("aliases of the third name = %q", got)
	}
}

// GAP-1432: a call that moves a directory sights it before it goes, as a
// plain directory with its identity.
func TestReachedEvidenceSightsTheDirectoryAMoveMoves(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(base, "new")
	if err := os.Mkdir(moved, 0o700); err != nil {
		t.Fatal(err)
	}
	targets := resolvedEvidence(t, "codex", base, "Bash", map[string]interface{}{"command": "mv new renamed"})
	if plain := ReachedPlainDirectories(targets); plain[moved] == "" || plain[moved] != DirectoryIdentity(moved) {
		t.Fatalf("the moved directory was not sighted: %v", plain)
	}
}
