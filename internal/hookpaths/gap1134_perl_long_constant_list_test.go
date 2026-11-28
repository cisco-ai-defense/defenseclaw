// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"
	"testing"
)

// gap1134PerlWritesHookFile reports whether the reader names the registered hook
// file (the path every row below writes or deliberately does not write).
func gap1134PerlWritesHookFile(code string) bool {
	for _, path := range literalInterpreterWrites(code, "perl", "/tmp", "/tmp") {
		if strings.HasSuffix(path, ".claude/settings.json") {
			return true
		}
	}
	return false
}

// TestGAP1134PerlLongConstantListRedefinesTheReadFlag pins GAP-1134 (substrate-1,
// RV-0592g A01): a use constant declaration longer than the bounded proof
// scan that also defines O_RDONLY as 1 turns sysopen(..., O_RDONLY) into a
// write of the registered hook file in real Perl; the reader must name the
// file (the tamper finding), not read the flag as the Fcntl read mode. The
// benign twin keeps a read flag the same long declaration leaves at 0.
func TestGAP1134PerlLongConstantListRedefinesTheReadFlag(t *testing.T) {
	long := "K0 => 0, K1 => 0, K2 => 0, K3 => 0, K4 => 0, K5 => 0, K6 => 0, K7 => 0, K8 => 0, K9 => 0, K10 => 0, K11 => 0, K12 => 0, K13 => 0, K14 => 0, K15 => 0, K16 => 0, K17 => 0, K18 => 0, K19 => 0, K20 => 0, K21 => 0, K22 => 0, K23 => 0, K24 => 0, K25 => 0, K26 => 0, K27 => 0, K28 => 0, K29 => 0, K30 => 0, K31 => 0, K32 => 0, K33 => 0, K34 => 0, K35 => 0, K36 => 0, K37 => 0, K38 => 0, K39 => 0, K40 => 0, K41 => 0, K42 => 0, K43 => 0, K44 => 0, K45 => 0, K46 => 0, K47 => 0, K48 => 0, K49 => 0, K50 => 0, K51 => 0, K52 => 0, K53 => 0, K54 => 0, K55 => 0, K56 => 0, K57 => 0, K58 => 0, K59 => 0, K60 => 0, K61 => 0, K62 => 0, K63 => 0, K64 => 0, K65 => 0, K66 => 0, K67 => 0, K68 => 0, K69 => 0, K70 => 0, K71 => 0, K72 => 0, K73 => 0, K74 => 0, K75 => 0, K76 => 0, K77 => 0, K78 => 0, K79 => 0, K80 => 0, K81 => 0, K82 => 0, K83 => 0, K84 => 0, K85 => 0, K86 => 0, K87 => 0, K88 => 0, K89 => 0"
	attack := "use constant { " + long + ", O_RDONLY => 1 }; sysopen(my $f,\".claude/settings.json\",O_RDONLY) or die $!; print $f \"x\""
	if !gap1134PerlWritesHookFile(attack) {
		t.Errorf("a long constant list that defines O_RDONLY as 1 is a write of the hook file in Perl; the reader named no write")
	}
	twin := "use constant { " + long + ", O_RDONLY => 0 }; sysopen(my $f,\".claude/settings.json\",O_RDONLY) or die $!; print <$f>"
	if gap1134PerlWritesHookFile(twin) {
		t.Errorf("a long constant list that leaves O_RDONLY at 0 is a read; the reader named a write")
	}
	ordinary := "open(my $f,\"<\",\".claude/settings.json\") or die $!; print <$f>"
	if gap1134PerlWritesHookFile(ordinary) {
		t.Errorf("an ordinary read of the hook file must stay a read")
	}
}
