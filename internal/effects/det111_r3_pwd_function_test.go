// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"slices"
	"testing"
)

// DET111 S4-R3, rel-1-0-10:GAP-1043: a pwd function defined in the call is not
// the builtin. $(pwd) (or `pwd`) after a definition that runs on every path
// and whose body is one echo of one static word reads that word; any other
// pwd function (a dynamic or optioned echo, a conditional, piped, background
// or later definition, an unset, a redefined echo) leaves $(pwd) unknown, and
// never the working folder.
func TestDET111R3PwdFunctionPrintsItsStaticWord(t *testing.T) {
	o := Options{Flavor: FlavorPOSIX, Home: "/home/dcku", CWD: "/home/dcku/proj",
		Env: map[string]string{"HOME": "/home/dcku"}}
	reads := func(command string) []string {
		var paths []string
		for _, e := range Extract(Call{Surface: SurfaceShell, Command: command}, o).Effects {
			if e.Kind == KindRead {
				paths = append(paths, e.Target.Path)
			}
		}
		return paths
	}
	for _, tc := range []struct{ command, want string }{
		{`pwd() { echo /home/other; }; cat $(pwd)/.ssh/id_rsa`, "/home/other/.ssh/id_rsa"},
		{"pwd() { echo /home/other; }; cat `pwd`/.aws/credentials", "/home/other/.aws/credentials"},
		{`function pwd { echo /home/other; }; cat "$(pwd)/.ssh/id_rsa"`, "/home/other/.ssh/id_rsa"},
		{`pwd() ( echo /srv/x ); cat $(pwd)/a`, "/srv/x/a"},
		{`pwd() { echo src; }; cat $(pwd)/a.py`, "/home/dcku/proj/src/a.py"},
		{`pwd() { echo /home/dcku/proj; }; cat $(pwd)/notes.txt`, "/home/dcku/proj/notes.txt"},
		{`pwd() { echo /a; }; pwd() { echo /b; }; cat $(pwd)/x`, "/b/x"},
		{`pwd() { echo /a; }; (pwd() { echo /b; }); cat $(pwd)/x`, "/a/x"},
		{`pwd() { echo /a; }; cd /tmp; cat $(pwd)/x`, "/a/x"},
	} {
		if got := reads(tc.command); !slices.Contains(got, tc.want) {
			t.Errorf("%q: read paths %q, want %q", tc.command, got, tc.want)
		}
	}
	for _, command := range []string{
		`cat $(pwd)/x; pwd() { echo /a; }`,
		`if true; then pwd() { echo /a; }; fi; cat $(pwd)/x`,
		`false && pwd() { echo /a; }; cat $(pwd)/x`,
		`pwd() { echo /a; } | cat; cat $(pwd)/x`,
		`pwd() { echo /a; } & cat $(pwd)/x`,
		`pwd() { echo "$X"; }; cat $(pwd)/x`,
		`pwd() { echo -n /a; }; cat $(pwd)/x`,
		`pwd() { echo /a /b; }; cat $(pwd)/x`,
		`pwd() { echo /a*; }; cat $(pwd)/x`,
		`pwd() { echo ~; }; cat $(pwd)/x`,
		`pwd() { echo /a\b; }; cat $(pwd)/x`,
		`pwd() { printf /a; }; cat $(pwd)/x`,
		`pwd() { echo /a; echo /b; }; cat $(pwd)/x`,
		`pwd() { echo /a >&2; }; cat $(pwd)/x`,
		`pwd() { echo /a; }; unset -f pwd; cat $(pwd)/x`,
		`echo() { :; }; pwd() { echo /a; }; cat $(pwd)/x`,
		`pwd() { echo /a; }; alias pwd=true; cat $(pwd)/x`,
	} {
		for _, p := range reads(command) {
			if p != "" {
				t.Errorf("%q: read path %q, want an unknown target", command, p)
			}
		}
	}
}
