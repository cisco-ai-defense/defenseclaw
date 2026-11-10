// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"testing"
)

// The apply_patch tools open a directive's file without any tab or carriage
// return in its name, wherever they stand, and without the white space that
// ends it; the content lines keep theirs.
func TestPatchTargetNameIsTheNameTheToolOpens(t *testing.T) {
	for _, tc := range []struct{ spelled, want string }{
		{".netrc", ".netrc"},
		{".ne\ttrc", ".netrc"},
		{"\t.netrc", ".netrc"},
		{".netrc\t", ".netrc"},
		{".ne\rtrc", ".netrc"},
		{".netrc\r", ".netrc"},
		{".aws/cred\tentials", ".aws/credentials"},
		{".aws/cred\t\rentials \t", ".aws/credentials"},
		{".netrc. ", ".netrc."},
		{"a b/c d", "a b/c d"},
		{" lead", " lead"},
	} {
		if got := PatchTargetName(tc.spelled); got != tc.want {
			t.Errorf("PatchTargetName(%q) = %q, want %q", tc.spelled, got, tc.want)
		}
	}
}

func patchDroppedCharsFacts(t *testing.T, field, directive, target, cwd string) Facts {
	t.Helper()
	body := map[string]string{"Add File": "\n+x", "Update File": "\n@@\n-a\n+b", "Delete File": ""}[directive]
	patch := "*** Begin Patch\n*** " + directive + ": " + target + body + "\n*** End Patch"
	if directive == "Move to" {
		patch = "*** Begin Patch\n*** Update File: old.txt\n*** Move to: " + target + "\n@@\n-a\n+b\n*** End Patch"
	}
	args, err := json.Marshal(map[string]string{field: patch})
	if err != nil {
		t.Fatal(err)
	}
	return Analyze(Input{Tool: "apply_patch", Args: args, CWD: cwd})
}

// A target spelled with a tab or a carriage return inside it, before it or
// after it is a fact for the file the tool opens, for every operation and
// input shape.
func TestAnalyzeApplyPatchReadsTargetsSpelledWithTabsAndCarriageReturns(t *testing.T) {
	access := map[string]PathAccess{
		"Add File": PathAccessWrite, "Update File": PathAccessWrite,
		"Delete File": PathAccessDelete, "Move to": PathAccessWrite,
	}
	for directive, want := range access {
		for _, field := range []string{"patch", "command", "input"} {
			for _, spelled := range []string{".ne\ttrc", "\t.netrc", ".netrc\t", ".ne\rtrc", ".netrc\r", "\r.netrc", ".n\te\rt\trc \t"} {
				facts := patchDroppedCharsFacts(t, field, directive, spelled, "/work")
				found := false
				for _, path := range facts.Paths {
					if path.Resolved == "/work/.netrc" && path.Access == want {
						found = true
					}
				}
				if !facts.Authoritative() || !found {
					t.Errorf("%s %s %q: facts = %#v, want /work/.netrc with access %v", field, directive, spelled, facts, want)
				}
			}
		}
	}
}

// A carriage return outside a directive line still leaves no readable
// envelope, and a spelling with a tab and the plain name are one target.
func TestAnalyzeApplyPatchStillRejectsCarriageReturnsOutsideDirectives(t *testing.T) {
	for _, patch := range []string{
		"*** Begin Patch\n*** Add File: a.txt\n+x\ry\n*** End Patch",
		"*** Begin Patch\n*** Add File: a.txt\n+x\n*** End Patch\r",
		"*** Begin Patch\n*** Update File: a.txt\n@@\r x\n-a\n+b\n*** End Patch",
		"*** Begin Patch\n*** Update File: a.txt\n@@\n-a\n+b\n*** End\rof File\n*** End Patch",
	} {
		args, err := json.Marshal(map[string]string{"patch": patch})
		if err != nil {
			t.Fatal(err)
		}
		if facts := Analyze(Input{Tool: "apply_patch", Args: args, CWD: "/work"}); facts.Parse.Status != StatusInvalid || facts.Authoritative() {
			t.Errorf("%q: facts = %#v, want an invalid envelope", patch, facts)
		}
	}
	args, err := json.Marshal(map[string]string{
		"patch": "*** Begin Patch\n*** Add File: .ne\ttrc\n+x\n*** Delete File: .netrc\n*** End Patch",
	})
	if err != nil {
		t.Fatal(err)
	}
	if facts := Analyze(Input{Tool: "apply_patch", Args: args}); facts.Parse.Status != StatusAmbiguous || facts.Authoritative() {
		t.Fatalf("spelled and plain target: facts = %#v", facts)
	}
}
