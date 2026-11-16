// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

// TestWindowsSeparatorSpellingKeepsShellEscapes pins the Windows reading the
// registration readers add on a Windows host: a backslash inside a word is a
// path separator, and one next to a blank, an operator, a quote or another
// backslash stays a shell escape.
func TestWindowsSeparatorSpellingKeepsShellEscapes(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ in, want string }{
		{`tar -xf b.tar -C C:\Users\me\.claude`, `tar -xf b.tar -C C:/Users/me/.claude`},
		{`find C:\work -name hook.json -exec rm {} \;`, `find C:/work -name hook.json -exec rm {} \;`},
		{`cp a "C:\Program Files\x"`, `cp a "C:/Program Files/x"`},
		{`ls my\ dir \\server\share`, `ls my\ dir \\server/share`},
		{`echo done`, `echo done`},
	} {
		if got := windowsSeparatorSpelling(tc.in); got != tc.want {
			t.Errorf("%q: got %q, want %q", tc.in, got, tc.want)
		}
	}
}
