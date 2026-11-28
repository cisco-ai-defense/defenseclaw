// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

// GAP-1139, GAP-1146, GAP-1147: a Perl open of a hook file whose mode or
// builtin may be changed by code the reader cannot prove (a required or done
// file, a definition inside a string eval, a mode changed by tr, an lvalue
// substr or a reference) gets no literal write operand, because no sound proof
// of the final mode exists in the command text. Each keeps the conservative
// unproven-write audit instead, so the hook-file open still alerts. The
// hook-file name is built from parts.
func TestGAP1139OpaquePerlModeKeepsUnprovenAudit(t *testing.T) {
	dir := t.TempDir()
	quoted := `"` + "." + "claude" + "/" + "settings" + ".json" + `"`
	perl := func(program string) string { return "perl -e '" + program + "'" }
	for _, tc := range []struct{ gap, name, command string }{
		{"GAP-1139", "required file", perl("our $m = \"<\"; require \"./m.pl\"; open(my $f, $m, " + quoted + ");")},
		{"GAP-1139", "required file, mode never set inline", perl("require \"./m.pl\"; open(my $f, $m, " + quoted + ");")},
		{"GAP-1139", "done file", perl("our $m = \"<\"; do \"./m.pl\"; open(my $f, $m, " + quoted + ");")},
		{"GAP-1146", "flag defined in a string eval", perl("eval \"sub O_RDONLY () { 1 }\"; sysopen(my $f, " + quoted + ", O_RDONLY);")},
		{"GAP-1146", "builtin defined in a string eval", perl("eval q{sub open { 1 }}; open(my $f, \"<\", " + quoted + ");")},
		{"GAP-1147", "transliterated mode", perl("my $m = \"<\"; $m =~ tr/</>/; open(my $f, $m, " + quoted + ");")},
		{"GAP-1147", "lvalue substr mode", perl("my $m = \"<\"; substr($m, 0, 1) = \">\"; open(my $f, $m, " + quoted + ");")},
		{"GAP-1147", "mode set through a reference", perl("my $m = \"<\"; my $r = \\$m; $$r = \">\"; open(my $f, $m, " + quoted + ");")},
	} {
		t.Run(tc.gap+" "+tc.name, func(t *testing.T) {
			if UnprovenProtectedWrite(tc.command, dir, dir) == "" {
				t.Fatalf("%s %s: the hook-file open lost the unproven-write audit", tc.gap, tc.name)
			}
		})
	}
}
