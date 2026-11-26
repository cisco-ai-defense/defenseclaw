// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"testing"
)

func TestPerlXargsMixedWritesKeepConservativeVerdict(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	code := `unlink("ordinary"); my $p = ".claude/settings.json"; open(my $fh, ">", $p);`
	for _, tc := range []struct{ name, command string }{
		{"pipeline", "printf item | xargs -I{} perl -e '" + code + "' {}"},
		{"direct", "xargs perl -e '" + code + "'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			operands := LiteralWriteOperands(tc.command, cwd, home)
			if got := ActionCommandDecision(tc.command, cwd, home); got == "" {
				t.Logf("action allowed; operands=%v", operands)
			}
			if tc.name == "direct" {
				if got := actionChildDecision([]string{"xargs", "perl", "-e", code}, nil, cwd, home, 0); got == "" {
					t.Fatal("direct xargs child bypassed conservative decision")
				}
			}
			if got := UnprovenProtectedWrite(tc.command, cwd, home); got == "" {
				t.Fatalf("mixed Perl writes lost conservative audit; operands=%v", operands)
			}
		})
	}
}
