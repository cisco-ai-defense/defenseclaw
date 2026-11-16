// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// The instruction identity of a write target reads the links of the target
// only when it can find one: the target exists and the call has an
// instruction file to compare it with (GAP-1075). Every operand of a long
// command paid that walk before, a read a folder and more on Windows. A
// link or second name of an instruction file is still identified.
func TestInstructionIdentityReadsTheLinksOfATargetOnlyWhenItCanMatter(t *testing.T) {
	for _, variable := range InstructionHomeVariables {
		t.Setenv(variable, "")
	}
	root := t.TempDir()
	home, cwd := filepath.Join(root, "home"), filepath.Join(root, "home", "proj")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	var targets []string
	for i := range 300 {
		target := filepath.Join(cwd, fmt.Sprintf("f%d", i))
		if i%2 == 0 {
			if err := os.WriteFile(target, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		targets = append(targets, target)
	}
	reads := func(files *InstructionFiles) int64 {
		before := instructionLinkReads.Load()
		for _, target := range targets {
			if named := files.Identities(target); len(named) != 0 {
				t.Fatalf("%s: ordinary target identified as %v", target, named)
			}
		}
		return instructionLinkReads.Load() - before
	}
	if n := reads(NewInstructionFiles(cwd, home, nil)); n != 0 {
		t.Errorf("no instruction file in the call: read the links of %d targets, want 0", n)
	}

	instruction := filepath.Join(cwd, "CLAUDE.md")
	if err := os.WriteFile(instruction, []byte("# rules\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if n := reads(NewInstructionFiles(cwd, home, nil)); n != int64(len(targets)/2) {
		t.Errorf("an instruction file in the call: read the links of %d targets, want the %d that exist", n, len(targets)/2)
	}
	second, link := filepath.Join(cwd, "notes.md"), filepath.Join(cwd, "rules-link")
	if err := os.Link(instruction, second); err != nil {
		t.Skipf("hard link: %v", err)
	}
	if err := os.Symlink(instruction, link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	files := NewInstructionFiles(cwd, home, nil)
	for _, alias := range []string{second, link} {
		if named := files.Identities(alias); !slices.Contains(named, instruction) {
			t.Errorf("%s: identified as %v, want %s", alias, named, instruction)
		}
	}
}
