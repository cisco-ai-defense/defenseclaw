// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package effects

import "testing"

// TestGAP2280TextReaderRowsKnowTheirOwnOptions: the text readers that shared
// one short-only flag set (comm, join, paste, fold, fmt, rev, column, expand,
// unexpand, strings, od, hexdump, look, df, file) each read with their own
// option grammar. A switch never takes the file operand as its value (column
// -t, od -c, strings -d, fmt -t), an option value never reads as a file
// (column -s SEP, hexdump -n LEN), and a long spelling reads as its short
// twin. So each command reads exactly as its plain twin. Red at 78506d3a71:
// the shared set gave -c -d -f -o -t -w -n a value and knew no long option.
func TestGAP2280TextReaderRowsKnowTheirOwnOptions(t *testing.T) {
	o := Options{Flavor: FlavorPOSIX, Dialect: DialectPOSIX, Home: "/home/u", CWD: "/home/u/proj",
		Env: map[string]string{"HOME": "/home/u"}}
	extract := func(o Options, command string) Result {
		return Extract(Call{Surface: SurfaceShell, Tool: "shell", Command: command, Workdir: o.CWD}, o)
	}
	const f, g, d = "/home/u/proj/a.txt", "/home/u/proj/b.txt", "/home/u/proj/src"
	two := " " + f + " " + g
	type row struct{ command, twin string }
	gnu := []row{
		{"comm -12" + two, "comm" + two},
		{"comm -3 --nocheck-order" + two, "comm" + two},
		{"comm --output-delimiter=, -z" + two, "comm" + two},
		{"comm --output-delimiter , --total" + two, "comm" + two},
		{"join -t , -1 2 -2 1" + two, "join" + two},
		{"join -a 1 -e x -o 1.1 -v 2" + two, "join" + two},
		{"join --ignore-case --header -j 1" + two, "join" + two},
		{"paste -d ," + two, "paste" + two},
		{"paste --delimiters=, -sz" + two, "paste" + two},
		{"fold -w 40 " + f, "fold " + f},
		{"fold --width=40 -bs " + f, "fold " + f},
		{"fold -80 " + f, "fold " + f},
		{"fmt -t " + f, "fmt " + f},
		{"fmt -c " + f, "fmt " + f},
		{"fmt -cs -w 60 " + f, "fmt " + f},
		{"fmt --width=60 --uniform-spacing --tagged " + f, "fmt " + f},
		{"fmt -p x -g 50 " + f, "fmt " + f},
		{"fmt -72 " + f, "fmt " + f},
		{"rev --version " + f, "rev " + f},
		{"column -t " + f, "column " + f},
		{"column -t -s , " + f, "column " + f},
		{"column -ts, " + f, "column " + f},
		{"column --table --separator=, " + f, "column " + f},
		{"column -x -c 80 " + f, "column " + f},
		{"column -J -N a,b -n t " + f, "column " + f},
		{"column -e -d -t -o x -L " + f, "column " + f},
		{"expand -t 4 " + f, "expand " + f},
		{"expand --tabs=4 -i " + f, "expand " + f},
		{"expand -4 " + f, "expand " + f},
		{"unexpand -a " + f, "unexpand " + f},
		{"unexpand -t 4 --first-only " + f, "unexpand " + f},
		{"strings -d " + f, "strings " + f},
		{"strings -o " + f, "strings " + f},
		{"strings -w -f " + f, "strings " + f},
		{"strings -a -n 8 " + f, "strings " + f},
		{"strings --bytes=8 -t x " + f, "strings " + f},
		{"strings -td -8 " + f, "strings " + f},
		{"strings -e l --data --print-file-name " + f, "strings " + f},
		{"od -c " + f, "od " + f},
		{"od -d " + f, "od " + f},
		{"od -o " + f, "od " + f},
		{"od -f " + f, "od " + f},
		{"od -x -v " + f, "od " + f},
		{"od -bc " + f, "od " + f},
		{"od -An -tx1 " + f, "od " + f},
		{"od -A x -t x1z -j 4 -N 8 " + f, "od " + f},
		{"od -w16 " + f, "od " + f},
		{"od -w " + f, "od " + f},
		{"od --width=16 --endian=big " + f, "od " + f},
		{"od -S 4 " + f, "od " + f},
		{"od --strings " + f, "od " + f},
		{"hexdump -C " + f, "hexdump " + f},
		{"hexdump -c " + f, "hexdump " + f},
		{"hexdump -n 16 -s 4 " + f, "hexdump " + f},
		{"hexdump -e x -v " + f, "hexdump " + f},
		{"hexdump --length=16 -Lalways " + f, "hexdump " + f},
		{"look -d abc " + f, "look abc " + f},
		{"look -f -t x abc " + f, "look abc " + f},
		{"look --alternative abc " + f, "look abc " + f},
		{"df -T " + d, "df " + d},
		{"df -h --output=source " + d, "df " + d},
		{"df -t ext4 -x tmpfs " + d, "df " + d},
		{"file -b " + f, "file " + f},
		{"file -i -L " + f, "file " + f},
		{"file --mime-type -E " + f, "file " + f},
		{"file -s -z " + f, "file " + f},
	}
	// The options only the BSD (macOS) tools take, by their system path.
	bsdOpt := o
	bsdOpt.BSDUserland = true
	bsdRows := []row{
		{"/usr/bin/fmt -l 4 -n " + f, "/usr/bin/fmt " + f},
		{"/usr/bin/fmt -d x -w 60 " + f, "/usr/bin/fmt " + f},
		{"/usr/bin/strings -arch arm64 -o " + f, "/usr/bin/strings " + f},
		{"/usr/bin/df -g -Y -l " + d, "/usr/bin/df " + d},
		{"/usr/bin/comm -i" + two, "/usr/bin/comm" + two},
	}
	check := func(o Options, rows []row) {
		for _, tc := range rows {
			want := extract(o, tc.twin)
			if len(want.Unknowns) != 0 || gap2273UnknownFlag(want) {
				t.Errorf("twin %q: an unknown, want none", tc.twin)
			}
			if g, w := gap2273Reading(extract(o, tc.command)), gap2273Reading(want); g != w {
				t.Errorf("%q:\n got %s\nwant %s (the twin %q)", tc.command, g, w, tc.twin)
			}
		}
	}
	check(o, gnu)
	check(bsdOpt, bsdRows)

	// A file an option names for the tool's own input is read too.
	for _, tc := range []struct{ command, read string }{
		{"hexdump -f " + g + " " + f, g},
		{"hexdump --format-file=" + g + " " + f, g},
		{"file -m " + g + " " + f, g},
		{"file --files-from " + g, g},
	} {
		r := extract(o, tc.command)
		read := false
		for _, e := range r.Effects {
			read = read || e.Kind == KindRead && e.Target.Path == tc.read && e.TargetState == TargetStateKnown && e.RoleState == RoleStateKnown
		}
		if !read || gap2273UnknownFlag(r) {
			t.Errorf("%q: %s, want a known read of %s", tc.command, gap2273Reading(r), tc.read)
		}
	}
	// An option the tool does not take, an ambiguous prefix, and a BSD flag
	// whose arity differs from the GNU row stay unknown.
	for _, tc := range []struct {
		o       Options
		command string
	}{
		{o, "column --tab " + f}, // --table, --table-name, ... are all prefixes
		{o, "strings -X " + f},
		{o, "od --bogus " + f},
	} {
		if !gap2273UnknownFlag(extract(tc.o, tc.command)) {
			t.Errorf("%q: no unknown, want the option left unknown", tc.command)
		}
	}
}
