// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

// TestNativeFileWriteThroughALinkTheClientPlacedOnSudoersIsProven: the hook
// client resolves the target as the user, so a link of any name that it placed
// on the main sudoers file or a direct drop-in is that file, and a grant
// written through it is proven like the direct write.
func TestNativeFileWriteThroughALinkTheClientPlacedOnSudoersIsProven(t *testing.T) {
	linksEtcForTest(t, true)
	grant := map[string]any{"file_path": "/work/proj/grant-link", "content": nativeSudoersGrant}
	for _, row := range []struct {
		name, cwd string
		args      map[string]any
		resolved  map[string]string
	}{
		{"link to the main file", "/work/proj", grant, map[string]string{"/work/proj/grant-link": "/etc/sudoers"}},
		{"link to a drop-in", "/work/proj", grant, map[string]string{"/work/proj/grant-link": "/etc/sudoers.d/ops"}},
		{"link to the macOS physical spelling", "/work/proj", grant, map[string]string{"/work/proj/grant-link": "/private/etc/sudoers"}},
		{"relative link name", "/work/proj", map[string]any{"file_path": "grant-link", "content": nativeSudoersGrant},
			map[string]string{"/work/proj/grant-link": "/etc/sudoers"}},
		{"dot-slash link name", "/work/proj", map[string]any{"file_path": "./grant-link", "content": nativeSudoersGrant},
			map[string]string{"/work/proj/grant-link": "/etc/sudoers"}},
		{"absolute path with a dot segment", "/work/proj", map[string]any{"file_path": "/work/proj/./grant-link", "content": nativeSudoersGrant},
			map[string]string{"/work/proj/grant-link": "/etc/sudoers"}},
		{"doubled slash and dot segment to a drop-in", "/work/proj", map[string]any{"file_path": "/work//proj/./grant-link", "content": nativeSudoersGrant},
			map[string]string{"/work/proj/grant-link": "/etc/sudoers.d/ops"}},
		{"leading dot-dot is cleaned by the client", "/work/proj", map[string]any{"file_path": "../proj/grant-link", "content": nativeSudoersGrant},
			map[string]string{"/work/proj/grant-link": "/etc/sudoers"}},
		{"inner dot-dot keeps the client raw key", "/work/proj", map[string]any{"file_path": "sub/../grant-link", "content": nativeSudoersGrant},
			map[string]string{"/work/proj/sub/../grant-link": "/etc/sudoers"}},
		{"absolute dot-dot keeps the client raw key", "/work/proj", map[string]any{"file_path": "/work/other/../proj/grant-link", "content": nativeSudoersGrant},
			map[string]string{"/work/other/../proj/grant-link": "/etc/sudoers"}},
		{"relative link name keyed as spelled", "/work/proj", map[string]any{"file_path": "grant-link", "content": nativeSudoersGrant},
			map[string]string{"grant-link": "/etc/sudoers"}},
	} {
		t.Run(row.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "Write", Args: nativeSudoersArgs(t, row.args), CWD: row.cwd, ClientResolvedTargets: row.resolved})
			if !ExactPOSIXUnrestrictedSudoersGrantWrite(facts) {
				t.Fatalf("missing grant proof for a write through a link to a sudoers file: %#v", facts.Parse)
			}
		})
	}
}

// TestNativeFileWriteThroughALinkElsewhereStaysUnproven is the benign twin: a
// link the client placed on an ordinary file, a comment or a root grant written
// through a sudoers link, a nested path and a call with no client evidence all
// stay without a proof.
func TestNativeFileWriteThroughALinkElsewhereStaysUnproven(t *testing.T) {
	linksEtcForTest(t, false)
	link := map[string]string{"/work/proj/grant-link": "/etc/sudoers"}
	for _, row := range []struct {
		name     string
		content  string
		resolved map[string]string
	}{
		{"link to an ordinary file", nativeSudoersGrant, map[string]string{"/work/proj/grant-link": "/work/proj/notes.txt"}},
		{"link to the drop-in directory", nativeSudoersGrant, map[string]string{"/work/proj/grant-link": "/etc/sudoers.d"}},
		{"link nested below the drop-in directory", nativeSudoersGrant, map[string]string{"/work/proj/grant-link": "/etc/sudoers.d/a/b"}},
		{"comment through a sudoers link", "# managed\n", link},
		{"root grant through a sudoers link", "root ALL=(ALL) NOPASSWD: ALL\n", link},
		{"evidence names another spelling", nativeSudoersGrant, map[string]string{"/work/proj/other-link": "/etc/sudoers"}},
		{"no client evidence", nativeSudoersGrant, nil},
		{"relative physical answer", nativeSudoersGrant, map[string]string{"/work/proj/grant-link": "etc/sudoers"}},
	} {
		t.Run(row.name, func(t *testing.T) {
			args := nativeSudoersArgs(t, map[string]any{"file_path": "/work/proj/grant-link", "content": row.content})
			facts := Analyze(Input{Tool: "Write", Args: args, CWD: "/work/proj", ClientResolvedTargets: row.resolved})
			if ExactPOSIXUnrestrictedSudoersGrantWrite(facts) {
				t.Fatal("a benign call produced a sudoers grant proof")
			}
		})
	}
}

// TestNativeFileWriteFromAProjectTheClientKeyedByAnotherNameIsProven: the
// gateway resolves a project reached through a link, the client keys a
// relative operand by the name it was given; the answer is found by either.
func TestNativeFileWriteFromAProjectTheClientKeyedByAnotherNameIsProven(t *testing.T) {
	linksEtcForTest(t, true)
	for _, operand := range []string{"grant-link", "./grant-link"} {
		args := nativeSudoersArgs(t, map[string]any{"file_path": operand, "content": nativeSudoersGrant})
		input := Input{Tool: "Write", Args: args, CWD: "/work/proj",
			ClientWorkingDirectories: []string{"/work/alias"},
			ClientResolvedTargets:    map[string]string{"/work/alias/grant-link": "/etc/sudoers"}}
		if !ExactPOSIXUnrestrictedSudoersGrantWrite(Analyze(input)) {
			t.Errorf("%s: missing grant proof for the directory spelling the client used", operand)
		}
		input.ClientWorkingDirectories = nil
		if ExactPOSIXUnrestrictedSudoersGrantWrite(Analyze(input)) {
			t.Errorf("%s: a client answer keyed in a directory the gateway was not told is not read", operand)
		}
		input.ClientWorkingDirectories = []string{"/work/alias"}
		input.ClientResolvedTargets = map[string]string{"/work/alias/grant-link": "/work/notes.txt"}
		if ExactPOSIXUnrestrictedSudoersGrantWrite(Analyze(input)) {
			t.Errorf("%s: a link to an ordinary file is not a grant target", operand)
		}
	}
}
