// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"
	"testing"
)

// gap1136PerlWritesHookFile reports whether the reader names the registered hook
// file (the path every row below writes or deliberately does not write).
func gap1136PerlWritesHookFile(code string) bool {
	for _, path := range literalInterpreterWrites(code, "perl", "/tmp", "/tmp") {
		if strings.HasSuffix(path, ".claude/settings.json") {
			return true
		}
	}
	return false
}

// TestGAP1136PerlBlockEvalQualifiedGlobRedefinesTheReadFlag pins GAP-1136
// (substrate-1, RV-0592g A03): eval { *main::O_RDONLY = sub () { 1 } } makes
// sysopen(..., O_RDONLY()) open the registered hook file for writing in real
// Perl; the reader must name the file. The benign twin assigns an unrelated
// glob and reads with the real flag.
func TestGAP1136PerlBlockEvalQualifiedGlobRedefinesTheReadFlag(t *testing.T) {
	attack := "eval { *main::O_RDONLY = sub () { 1 } }; sysopen(my $f,\".claude/settings.json\",O_RDONLY()) or die $!; print $f \"x\""
	if !gap1136PerlWritesHookFile(attack) {
		t.Errorf("a block eval that assigns the qualified glob O_RDONLY makes the open a write in Perl; the reader named no write")
	}
	twin := "use Fcntl; eval { *main::HELPER = sub () { 1 } }; sysopen(my $f,\".claude/settings.json\",O_RDONLY()) or die $!; print <$f>"
	if gap1136PerlWritesHookFile(twin) {
		t.Errorf("an unrelated glob assignment leaves O_RDONLY a read; the reader named a write")
	}
}
