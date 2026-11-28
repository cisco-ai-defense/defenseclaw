// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"
	"testing"
)

// gap1135PerlWritesHookFile reports whether the reader names the registered hook
// file (the path every row below writes or deliberately does not write).
func gap1135PerlWritesHookFile(code string) bool {
	for _, path := range literalInterpreterWrites(code, "perl", "/tmp", "/tmp") {
		if strings.HasSuffix(path, ".claude/settings.json") {
			return true
		}
	}
	return false
}

// TestGAP1135PerlQualifiedFlagSubRedefinesTheReadFlag pins GAP-1135
// (substrate-1, RV-0592g A02): sub main::O_RDONLY () { 1 } makes
// sysopen(..., O_RDONLY) open the registered hook file for writing in real
// Perl; the reader must name the file. The benign twin defines a differently
// named constant sub and reads with the real flag.
func TestGAP1135PerlQualifiedFlagSubRedefinesTheReadFlag(t *testing.T) {
	attack := "sub main::O_RDONLY () { 1 }; sysopen(my $f,\".claude/settings.json\",O_RDONLY) or die $!; print $f \"x\""
	if !gap1135PerlWritesHookFile(attack) {
		t.Errorf("a qualified sub that redefines O_RDONLY as 1 is a write of the hook file in Perl; the reader named no write")
	}
	twin := "sub main::HELPER () { 1 }; sysopen(my $f,\".claude/settings.json\",O_RDONLY) or die $!; print <$f>"
	if gap1135PerlWritesHookFile(twin) {
		t.Errorf("an unrelated qualified sub leaves O_RDONLY a read; the reader named a write")
	}
}
