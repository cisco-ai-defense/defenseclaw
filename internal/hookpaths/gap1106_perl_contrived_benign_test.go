// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"
	"testing"
)

// gap1106PerlWritesHookFile reports whether the reader names the registered hook
// file (the path every row below writes or deliberately does not write).
func gap1106PerlWritesHookFile(code string) bool {
	for _, path := range literalInterpreterWrites(code, "perl", "/tmp", "/tmp") {
		if strings.HasSuffix(path, ".claude/settings.json") {
			return true
		}
	}
	return false
}

// TestGAP1106PerlContrivedBenignProgramsAreNotWritesOfTheHookFile pins GAP-1106
// (substrate-1, RV-0592b B10 and B14): a program whose unlink of the hook
// file is data after a mid-line __END__, or a call of a user sub that is
// named unlink (&unlink), never touches the file in real Perl and the reader
// must not name it (rel allows both). The twin is a plain
// three-argument write open of the same file, which must stay named.
func TestGAP1106PerlContrivedBenignProgramsAreNotWritesOfTheHookFile(t *testing.T) {
	const hook = ".claude/settings.json"
	for name, code := range map[string]string{
		"B10 mid-line __END__":     "print 1; __END__ unlink \"" + hook + "\"",
		"B14 and &unlink user sub": "sub unlink { print 1 } 1 and &unlink(\"" + hook + "\")",
	} {
		if gap1106PerlWritesHookFile(code) {
			t.Errorf("%s: real Perl leaves the hook file unchanged; the reader named a write", name)
		}
	}
	if !gap1106PerlWritesHookFile("open(F,\">\",\"" + hook + "\");") {
		t.Errorf("a plain write open of the hook file must stay a named write")
	}
}
