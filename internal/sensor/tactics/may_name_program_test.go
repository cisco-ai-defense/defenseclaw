// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package tactics

import (
	"math/rand/v2"
	"strings"
	"testing"
)

// TestMayNameProgramHoldsWhereRunsProgramRuns is the exactness of the
// MayNameProgram check (rel-1-0-10:GAP-0299): a text it rejects is never one
// RunsProgram reads as running one of the programs, whatever quotes,
// escapes, wrappers, nested scripts and case spell the name.
func TestMayNameProgramHoldsWhereRunsProgramRuns(t *testing.T) {
	names := []string{"apply_patch", "applypatch", "apply-patch"}
	runs := []string{
		"apply_patch", "APPLY_PATCH < p", "sudo -u root env apply_patch", "'apply'_patch", `"app""ly_patch"`,
		"bash -c 'apply_patch <x'", `eval "apply_patch"`, "x=$(apply_patch)", "`apply_patch`",
		"/usr/bin/apply_patch.exe", `C:\tools\Apply_Patch.EXE`, "ap\\\nply_patch", "cmd /c apply-patch",
		"echo hi | applypatch", "sh -c \"a'p'p\\\"\\\"ly_patch\"", "env --chdir=x apply_patch",
	}
	for _, command := range runs {
		if !RunsProgram(command, names...) {
			t.Fatalf("corpus: RunsProgram(%q) = false", command)
		}
		if !MayNameProgram(command, names...) {
			t.Errorf("MayNameProgram(%q) = false where RunsProgram runs it", command)
		}
	}
	for _, command := range []string{"", "cat > notes.txt <<'EOF'\nthe plan, patched and applied\nEOF\n", "apply patch", "apply_pat ch"} {
		if MayNameProgram(command, names...) {
			t.Errorf("MayNameProgram(%q) = true for a text that names none", command)
		}
	}
	if !MayNameProgram("anything", "Apply_Patch") || !MayNameProgram("anything", "a b") || MayNameProgram("apply_patch") {
		t.Error("a name outside lowercase ASCII is not checked, and no program is never named")
	}
	// Random texts of name pieces, quotes, escapes, newlines, wrappers,
	// nested scripts, here-documents, comments and non-ASCII bytes (the
	// dotted capital I lowers to i, so it can spell pip).
	pieces := []string{
		"apply", "_", "patch", "-", "pip", "P", "\u0130", "\xc4", "\xb0", ".exe", "/", `\`, "'", `"`, "\n", " ", ";",
		"|", "$(", ")", "`", "bash -c ", "eval ", "sudo ", "env ", "cmd /c ", "<<E\n", "E\n", "#", "x", "A", "=",
	}
	random := rand.New(rand.NewPCG(299, 1))
	programs := []string{"apply_patch", "pip", "applypatch"}
	ran := 0
	for range 60000 {
		var text strings.Builder
		for range 1 + random.IntN(12) {
			text.WriteString(pieces[random.IntN(len(pieces))])
		}
		command := text.String()
		if !RunsProgram(command, programs...) {
			continue
		}
		ran++
		if !MayNameProgram(command, programs...) {
			t.Fatalf("MayNameProgram(%q) = false where RunsProgram runs it", command)
		}
	}
	if ran < 1000 {
		t.Fatalf("only %d random texts run a program: the corpus proves little", ran)
	}
}
