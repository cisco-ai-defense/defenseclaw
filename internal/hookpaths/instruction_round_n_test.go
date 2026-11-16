// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
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

// GAP-1432, GAP-0474: a call that moves a directory sights it before it goes,
// as a plain directory with its identity, even when cwd is outside the home.
func TestReachedEvidenceSightsTheDirectoryAMoveMoves(t *testing.T) {
	check := func(t *testing.T, base string) {
		t.Helper()
		moved := filepath.Join(base, "new")
		if err := os.Mkdir(moved, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, connector := range []string{"claudecode", "codex"} {
			targets := resolvedEvidence(t, connector, base, "Bash", map[string]interface{}{"command": "mv new renamed"})
			if plain := ReachedPlainDirectories(targets); plain[moved] == "" || plain[moved] != DirectoryIdentity(moved) {
				t.Errorf("%s: the moved directory was not sighted: %v", connector, plain)
			}
		}
	}
	check(t, moveSightingTestDir(t, t.TempDir()))
	if runtime.GOOS == "windows" {
		var outside string
		parents := []string{`C:\Users\Public`}
		if winDir := os.Getenv("SystemRoot"); filepath.IsAbs(winDir) {
			parents = append([]string{filepath.Join(winDir, "Temp")}, parents...)
		}
		for _, parent := range parents {
			if parent == "" {
				continue
			}
			if base, err := os.MkdirTemp(parent, "dc-hp474-"); err == nil {
				outside = base
				t.Cleanup(func() { _ = os.RemoveAll(base) })
				break
			}
		}
		if outside == "" {
			t.Fatal("could not create an outside-profile test directory")
		}
		if home, err := os.UserHomeDir(); err == nil {
			if relative, err := filepath.Rel(home, outside); err == nil &&
				(relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator))) {
				t.Fatalf("outside-profile test directory %q is inside home %q", outside, home)
			}
		}
		t.Run("outside-profile", func(t *testing.T) { check(t, outside) })
		for drive := 'C'; drive <= 'Z'; drive++ {
			volume := fmt.Sprintf("%c:\\", drive)
			if filepath.VolumeName(volume) == filepath.VolumeName(outside) {
				continue
			}
			if other, err := os.MkdirTemp(volume, "dc-hp474-"); err == nil {
				t.Cleanup(func() { _ = os.RemoveAll(other) })
				t.Run("other-volume", func(t *testing.T) { check(t, other) })
				break
			}
		}
	}
}

func moveSightingTestDir(t *testing.T, parent string) string {
	t.Helper()
	base, err := os.MkdirTemp(parent, "dc-hp474-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	base, err = filepath.EvalSymlinks(base)
	if err != nil {
		t.Fatal(err)
	}
	return base
}
