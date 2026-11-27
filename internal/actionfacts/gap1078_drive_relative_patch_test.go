// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"slices"
	"testing"
)

// rel-1-0-10:GAP-1078: on a Windows host a drive-relative patch header
// (C:name) on the drive of the working folder names the file of that folder,
// as Win32 opens it: it is the path fact of the same file under its full
// name, in every directive and patch field, its content is read for that
// file, and the call is not reported unplaced. A header on another drive (its
// current folder is not known) and a bare drive stay unplaced. Before the fix
// every C:name read as unplaced (the unknown tier) where the full name is
// judged by the path rules.
func TestGAP1078DriveRelativePatchHeaderIsPlacedAgainstTheWorkingFolder(t *testing.T) {
	windowsPatchNames(t)
	const cwd = `C:\Users\fixture`
	for _, tc := range []struct{ header, full string }{
		{`C:.ssh\authorized_keys`, `C:\Users\fixture\.ssh\authorized_keys`},
		{`c:notes.txt`, `C:\Users\fixture\notes.txt`},
		{`C:sub/notes.txt`, `C:\Users\fixture\sub/notes.txt`},
	} {
		for directive, envelope := range patchHeaderEnvelopes(tc.header) {
			for _, field := range patchHeaderFields {
				t.Run(directive+" "+field+" "+tc.header, func(t *testing.T) {
					args, err := json.Marshal(map[string]string{field: envelope.text})
					if err != nil {
						t.Fatal(err)
					}
					input := Input{Tool: "apply_patch", Args: args, CWD: cwd, DialectHint: DialectPowerShell}
					facts := Analyze(input)
					if !facts.Authoritative() {
						t.Fatalf("parse = %#v", facts.Parse)
					}
					if !slices.ContainsFunc(facts.Paths, func(path PathFact) bool {
						return path.Value == tc.full && path.Access == envelope.access
					}) {
						t.Fatalf("no %s fact for %s: %#v", envelope.access, tc.full, facts.Paths)
					}
					if PatchNamesUnplacedTarget(input) {
						t.Fatal("a header on the working folder's drive is reported unplaced")
					}
					if directive != "delete" && !slices.Contains(NativeFileWriteTargets(input), tc.full) {
						t.Fatalf("the content readers do not read %s: %v", tc.full, NativeFileWriteTargets(input))
					}
				})
			}
		}
	}
	for _, tc := range []struct{ header, cwd string }{
		{`D:notes.txt`, cwd}, {`C:notes.txt`, `D:\work`}, {`C:`, cwd}, {`C:notes.txt`, ""},
	} {
		args, _ := json.Marshal(map[string]string{"command": "*** Begin Patch\n*** Add File: " + tc.header + "\n+x\n*** End Patch"})
		input := Input{Tool: "apply_patch", Args: args, CWD: tc.cwd, DialectHint: DialectPowerShell}
		if !PatchNamesUnplacedTarget(input) {
			t.Errorf("%s with the working folder %q is not reported unplaced", tc.header, tc.cwd)
		}
		if Analyze(input).Authoritative() {
			t.Errorf("%s with the working folder %q is a fact", tc.header, tc.cwd)
		}
	}
}
