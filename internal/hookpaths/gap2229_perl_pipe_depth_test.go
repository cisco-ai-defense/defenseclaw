// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A Perl pipe command is read by the shell reader one level below the shell
// that runs the Perl, so alternating Perl and shell layers share the bound of
// the shell reader's nesting instead of starting again at depth 1 at every
// Perl pipe (rel-1-0-10:GAP-2229). As for a sh -c body, the redirects of a
// pipe command are read at the level of the descent and its commands one
// level deeper, up to depth 4.
func TestGAP2229PerlPipeKeepsShellReaderDepth(t *testing.T) {
	shellQuote := func(s string) string {
		return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
	}
	// perlLiteral is s as a Perl expression of fixed strings: '...' pieces
	// joined with "'" where s has a single quote.
	perlLiteral := func(s string) string {
		return "'" + strings.ReplaceAll(s, "'", `' . "'" . '`) + "'"
	}
	// command is the Perl of perls layers, each piping to the next and the
	// last to a redirect to p, run by shells sh -c shells deep.
	command := func(shells, perls int) string {
		code := `open(F,"|echo x > p");`
		for i := 1; i < perls; i++ {
			code = `open(F,"|-",` + perlLiteral("perl -e "+shellQuote(code)) + `);`
		}
		text := "perl -e " + shellQuote(code)
		for i := 0; i < shells; i++ {
			text = "sh -c " + shellQuote(text)
		}
		return text
	}
	cwd := t.TempDir()
	want := filepath.Join(cwd, "p")
	cases := []struct {
		shells, perls int
		read          bool
	}{
		// Each sh -c and each Perl pipe is one level: the innermost redirect
		// is read while the levels are at most 5.
		{0, 1, true}, {4, 1, true}, {5, 1, false},
		{3, 2, true}, {4, 2, false},
		{2, 3, true}, {3, 3, false},
		{0, 4, true}, {1, 4, true}, {2, 4, false},
	}
	for _, tc := range cases {
		got := LiteralWriteOperands(command(tc.shells, tc.perls), cwd, cwd)
		if slices.Contains(got, want) != tc.read {
			t.Errorf("%d sh -c around %d Perl layers: operands %v, want read %v", tc.shells, tc.perls, got, tc.read)
		}
	}
}
