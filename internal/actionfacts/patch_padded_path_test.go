// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"testing"
)

// A directive line is read without the white space that ends it, as the
// apply_patch tools read it: a padded target is a fact for the file it names,
// for every operation and in both input shapes, and white space that begins
// the path or is the whole path still leaves no readable envelope.
func TestAnalyzeApplyPatchReadsTargetsPaddedAtTheEnd(t *testing.T) {
	bodies := map[string]string{
		"Add File":    "\n+x",
		"Update File": "\n@@\n-a\n+b",
		"Delete File": "",
	}
	access := map[string]PathAccess{
		"Add File": PathAccessWrite, "Update File": PathAccessWrite, "Delete File": PathAccessDelete,
	}
	for directive, body := range bodies {
		for _, field := range []string{"patch", "command"} {
			for _, padded := range []string{"a.go ", "a.go  ", "a.go\t", "a.go. ", "a.go\u00a0"} {
				patch := "*** Begin Patch\n*** " + directive + ": " + padded + body + "\n*** End Patch"
				args, err := json.Marshal(map[string]string{field: patch})
				if err != nil {
					t.Fatal(err)
				}
				facts := Analyze(Input{Tool: "apply_patch", Args: args, CWD: "/work"})
				want := "/work/a.go"
				if padded == "a.go. " {
					want = "/work/a.go."
				}
				if !facts.Authoritative() || len(facts.Paths) != 1 ||
					facts.Paths[0].Resolved != want || facts.Paths[0].Access != access[directive] {
					t.Errorf("%s %s %q: facts = %#v", field, directive, padded, facts)
				}
			}
			for _, bad := range []string{" a.go", "\u00a0a.go", "  "} {
				patch := "*** Begin Patch\n*** " + directive + ": " + bad + body + "\n*** End Patch"
				args, err := json.Marshal(map[string]string{field: patch})
				if err != nil {
					t.Fatal(err)
				}
				facts := Analyze(Input{Tool: "apply_patch", Args: args, CWD: "/work"})
				if facts.Parse.Status != StatusInvalid || facts.Authoritative() || len(facts.Paths) != 0 {
					t.Errorf("%s %s %q: facts = %#v, want an invalid envelope", field, directive, bad, facts)
				}
			}
		}
	}
}

// The same target spelled with and without the padding is one path: a file an
// envelope names in two blocks is read block by block (GAP-1037), both blocks
// naming the same file.
func TestAnalyzeApplyPatchPaddedAndPlainTargetAreOneFile(t *testing.T) {
	args, err := json.Marshal(map[string]string{
		"patch": "*** Begin Patch\n*** Add File: a.go \n+x\n*** Delete File: a.go\n*** End Patch",
	})
	if err != nil {
		t.Fatal(err)
	}
	facts := Analyze(Input{Tool: "apply_patch", Args: args, CWD: "/work"})
	if facts.Parse.Status != StatusComplete || len(facts.Paths) != 2 ||
		facts.Paths[0].Resolved != "/work/a.go" || facts.Paths[1].Resolved != "/work/a.go" ||
		facts.Paths[0].Access != PathAccessWrite || facts.Paths[1].Access != PathAccessDelete {
		t.Fatalf("facts = %#v", facts)
	}
}
