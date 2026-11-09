// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package assetfacts

import (
	"os"
	"path/filepath"
	"testing"
)

// A slash-free word that names an existing entry in the working folder is a
// path, spelled as ./word is: a link to a skill folder is followed for every
// reader, and SKILL.md read from inside a skill folder is the manifest. A word
// that names nothing there stays a word.
func TestBareOperandThatNamesAnExistingEntryIsAPath(t *testing.T) {
	home, root, held := skillTree(t)
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proj, "notes.txt"), []byte("notes"), 0o644); err != nil {
		t.Fatal(err)
	}
	linkOrSkip(t, held, filepath.Join(proj, "lnk-held"))
	linkOrSkip(t, filepath.Join(proj, "lnk-held"), filepath.Join(proj, "lnk-chain"))

	reach := func(input map[string]any, cwd string) (FolderRef, bool) {
		for _, ref := range SkillFolderRefs(input, home, cwd) {
			if ref.Dir == held {
				return ref, true
			}
		}
		return FolderRef{}, false
	}
	for name, input := range map[string]map[string]any{
		"read":             {"file_path": "lnk-held"},
		"grep":             {"path": "lnk-held", "pattern": "x"},
		"glob":             {"path": "lnk-held", "pattern": "*"},
		"ls":               {"command": "ls lnk-held"},
		"recursive":        {"command": "grep -r token lnk-held"},
		"link chain":       {"command": "cat lnk-chain"},
		"leading cd":       {"command": "cd lnk-held && ls"},
		"cd then manifest": {"command": "cd lnk-held; cat SKILL.md"},
	} {
		t.Run(name, func(t *testing.T) {
			ref, ok := reach(input, proj)
			if !ok || !ref.BareOperand {
				t.Fatalf("%v: ref to the folder = %+v ok=%t, want it, marked as a bare operand", input, ref, ok)
			}
		})
	}
	// From inside the folder, SKILL.md names the manifest.
	if ref, ok := reach(map[string]any{"command": "cat SKILL.md"}, held); !ok || !ref.Manifest {
		t.Errorf("SKILL.md from inside the folder: %+v ok=%t, want the manifest of the folder", ref, ok)
	}
	// Ordinary words stay words: commands, flags, a missing name, a plain file.
	for name, input := range map[string]map[string]any{
		"echo":          {"command": "echo hello lnk-held-not-here"},
		"missing":       {"command": "ls nothing-here"},
		"flags":         {"command": "grep -n token notes.txt"},
		"ordinary file": {"file_path": "notes.txt"},
	} {
		t.Run("twin "+name, func(t *testing.T) {
			if refs := SkillFolderRefs(input, home, proj); len(refs) != 0 {
				t.Fatalf("%v: refs = %+v, want none", input, refs)
			}
		})
	}
	// A word that is no entry of the skills root names no skill folder.
	if refs := SkillFolderRefs(map[string]any{"command": "echo other"}, home, root); len(refs) != 0 {
		t.Errorf("a word that names no entry of the skills root: refs = %+v, want none", refs)
	}
}
