// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"testing"
)

// The lexical patch parse lists every directive placed in cwd and home, with
// no filesystem walk, so a gateway that cannot read a private project still
// names the absolute, home-form and relative targets the hook resolved.
func TestApplyPatchLexicalTargetsListsEveryDirectiveForm(t *testing.T) {
	root := t.TempDir()
	cwd := filepath.Join(root, "unreadable", "project")
	home := filepath.Join(root, "home")
	abs := filepath.Join(cwd, "abs.txt")
	patch := "*** Begin Patch\n*** Add File: " + abs + "\n+a\n*** Update File: rel.txt\n*** Move to: " +
		filepath.Join(cwd, "moved.txt") + "\n@@\n-x\n+y\n*** Delete File: ~/notes.txt\n*** End Patch\n"
	args, _ := json.Marshal(map[string]string{"patch": patch})
	got, ok := ApplyPatchLexicalTargets("apply_patch", args, cwd, home)
	if !ok {
		t.Fatalf("lexical parse refused a complete patch")
	}
	for _, want := range []string{abs, filepath.Join(cwd, "rel.txt"), filepath.Join(cwd, "moved.txt"), filepath.Join(home, "notes.txt")} {
		if !slices.Contains(got, want) {
			t.Fatalf("lexical targets %v miss %s", got, want)
		}
	}
	if _, ok := ApplyPatchLexicalTargets("Bash", args, cwd, home); ok {
		t.Fatalf("only an apply_patch tool call has lexical patch targets")
	}
	bad, _ := json.Marshal(map[string]string{"patch": "*** Begin Patch\n*** Add File: $X/a\n+a\n*** End Patch\n"})
	if _, ok := ApplyPatchLexicalTargets("apply_patch", bad, cwd, home); ok {
		t.Fatalf("an expanding directive has no lexical target")
	}
}
