// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"
	"testing"
)

// GAP-1097: inline Perl writes to a hook file through forms beyond a literal
// builtin operand. Each form must surface the hook file as a write operand or
// keep the conservative unproven-write audit (UnprovenProtectedWrite), so it
// alerts in default and blocks in strict. perl5.36 is the same program as
// perl (a versioned binary). The hook-file name is built from parts.
func TestGAP1097PerlHookFileWriteForms(t *testing.T) {
	dir := t.TempDir()
	folder := "." + "claude"
	target := folder + "/" + "settings" + ".json"
	quoted := `"` + target + `"`
	perl := func(program string) string { return "perl -e '" + program + "'" }
	for _, tc := range []struct{ name, command string }{
		{"q braces", perl("open(my $f, \">\", q{" + target + "});")},
		{"qq braces", perl("unlink(qq{" + target + "});")},
		{"concatenated", perl("unlink(\"" + folder + "/sett\" . \"ings.json\");")},
		{"system tee", perl("system(\"tee\", " + quoted + ");")},
		{"system shell", perl("system(\"echo x > " + target + "\");")},
		{"qx", perl("qx(echo x > " + target + ");")},
		{"exec tee", perl("exec(\"tee\", " + quoted + ");")},
		{"rmtree", perl("use File::Path qw(rmtree); rmtree(\"" + folder + "\");")},
		{"IO::File", perl("use IO::File; my $f = IO::File->new(" + quoted + ", \"w\");")},
		{"second -e", "perl -e 'print 1;' -e 'unlink " + quoted + ";'"},
		{"in-place variable", perl("$^I = \"\"; @ARGV = (" + quoted + "); while (<>) { print }")},
		{"versioned perl", "perl5.36 -e 'unlink " + quoted + ";'"},
		{"glob", perl("unlink glob(\"" + folder + "/*.json\");")},
		{"format body", perl("format STDOUT =\n@<<<\n$x\n.\nunlink " + quoted + ";\n")},
		{"CORE rename through a ref", perl("my $r = \\&CORE::rename; $r->(\"a\", " + quoted + ");")},
		{"CORE rename through a ref call", perl("my $r = \\&CORE::rename; &$r(\"a\", " + quoted + ");")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, path := range LiteralWriteOperands(tc.command, dir, dir) {
				if strings.Contains(path, folder) {
					return
				}
			}
			if UnprovenProtectedWrite(tc.command, dir, dir) == "" {
				t.Fatalf("hook-file write form %s: no write operand and no unproven-write audit (GAP-1097)", tc.name)
			}
		})
	}
}
