// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"fmt"
	"slices"
	"testing"
)

// gap2273UnknownFlag reports an effect that carries the unknown-flag reason.
func gap2273UnknownFlag(r Result) bool {
	for _, e := range r.Effects {
		for _, reason := range e.Reasons {
			if reason.Code == ReasonUnknownFlag {
				return true
			}
		}
	}
	return false
}

// gap2273Reading is what a call's operands read: each effect's kind, target,
// target and role state and whether it is shown, plus the unknown count.
func gap2273Reading(r Result) string {
	var out []string
	for _, e := range r.Effects {
		out = append(out, fmt.Sprintf("%s %s %s/%s shown=%t", e.Kind, e.Target.Path, e.TargetState, e.RoleState, e.Shown))
	}
	slices.Sort(out)
	return fmt.Sprintf("%v unknowns=%d", out, len(r.Unknowns))
}

// TestGAP2273ReaderRowsKnowTheirOwnOptions: every reader row is its tool's
// own option grammar (GNU coreutils and diffutils --help on the build box),
// long options and value arity included. A switch never takes the next word
// (wc -c, md5sum -c, readlink -f, du -c, stat -f, diff -w), an option with a
// value never leaves it as a file (cut -b LIST, diff -U NUM, diff -I RE), and
// a long spelling or prefix reads as its short twin. So each command reads
// exactly as its twin. Red at b366a390e3: the rows shared one short-only
// flag set, so a long option was an unknown flag and a switch or a value
// moved the operands.
func TestGAP2273ReaderRowsKnowTheirOwnOptions(t *testing.T) {
	o := Options{Flavor: FlavorPOSIX, Dialect: DialectPOSIX, Home: "/home/u", CWD: "/home/u/proj",
		Env: map[string]string{"HOME": "/home/u"}}
	extract := func(command string) Result {
		return Extract(Call{Surface: SurfaceShell, Tool: "shell", Command: command, Workdir: o.CWD}, o)
	}
	const f, g, d = "/home/u/proj/a.txt", "/home/u/proj/b.txt", "/home/u/proj/src"
	for _, tc := range []struct{ command, twin string }{
		// wc and the digest tools: summary readers.
		{"wc -c " + f + " " + g, "wc " + f + " " + g},
		{"wc --bytes " + f + " " + g, "wc " + f + " " + g},
		{"wc --by " + f, "wc " + f},
		{"wc -lw --chars " + f, "wc " + f},
		{"wc --total=never " + f, "wc " + f},
		{"wc --total never " + f, "wc " + f},
		{"md5sum -c " + f, "md5sum " + f},
		{"md5sum --check --quiet " + f, "md5sum " + f},
		{"sha256sum --ch " + f, "sha256sum " + f},
		{"sha1sum --check " + f, "sha1sum " + f},
		{"sha512sum -c --strict " + f, "sha512sum " + f},
		{"b2sum -l 256 " + f, "b2sum " + f},
		{"b2sum --length=256 -c " + f, "b2sum " + f},
		{"cksum -a sha256 " + f, "cksum " + f},
		{"cksum --algorithm sha256 --untagged " + f, "cksum " + f},
		{"shasum -a 256 " + f, "shasum " + f},
		{"shasum --algorithm 256 --check " + f, "shasum " + f},
		// cut.
		{"cut -b 1-3 " + f, "cut -c 1-3 " + f},
		{"cut --bytes=1-3 " + f, "cut -c 1-3 " + f},
		{"cut --fields=1 " + f, "cut -f 1 " + f},
		{"cut --delimiter , -f1 " + f, "cut -d , -f1 " + f},
		{"cut -n -b1 " + f, "cut -c1 " + f},
		{"cut --output-delimiter=: --complement -f1 " + f, "cut -f1 " + f},
		{"cut --only-delimited -z -f1 " + f, "cut -f1 " + f},
		// diff.
		{"diff -w " + f + " " + g, "diff " + f + " " + g},
		{"diff -c " + f + " " + g, "diff " + f + " " + g},
		{"diff -d -t " + f + " " + g, "diff " + f + " " + g},
		{"diff -u " + f + " " + g, "diff " + f + " " + g},
		{"diff -U 5 " + f + " " + g, "diff " + f + " " + g},
		{"diff -C 2 " + f + " " + g, "diff " + f + " " + g},
		{"diff --unified=5 " + f + " " + g, "diff " + f + " " + g},
		{"diff --context " + f + " " + g, "diff " + f + " " + g},
		{"diff -I todo " + f + " " + g, "diff " + f + " " + g},
		{"diff --ignore-all-space --ignore-case " + f + " " + g, "diff " + f + " " + g},
		{"diff --label x --label y " + f + " " + g, "diff " + f + " " + g},
		{"diff --brief " + f + " " + g, "diff -q " + f + " " + g},
		{"diff --from-file=" + f + " " + g, "diff " + f + " " + g},
		{"diff -r -x build " + d + " /home/u/proj/dst", "diff -r " + d + " /home/u/proj/dst"},
		{"diff --old-line-format=x " + f + " " + g, "diff " + f + " " + g},
		// The metadata rows.
		{"du -c " + d + " /home/u/proj/doc", "du " + d + " /home/u/proj/doc"},
		{"du --max-depth=1 " + d, "du -d 1 " + d},
		{"du -B 1K --summarize " + d, "du " + d},
		{"du --exclude=build -sh " + d, "du " + d},
		{"du --time " + d, "du " + d},
		{"stat -f " + f, "stat " + f},
		{"stat --format=%s " + f, "stat -c %s " + f},
		{"stat --printf=%s --dereference " + f, "stat " + f},
		{"readlink -f " + f, "readlink " + f},
		{"readlink --canonicalize -n " + f, "readlink " + f},
		{"realpath --relative-to=/home/u " + f, "realpath " + f},
		{"realpath --relative-to /home/u -s " + f, "realpath " + f},
		{"realpath --no-symlinks " + f, "realpath " + f},
	} {
		want := extract(tc.twin)
		if len(want.Unknowns) != 0 || gap2273UnknownFlag(want) {
			t.Errorf("twin %q: an unknown, want none", tc.twin)
		}
		if g, w := gap2273Reading(extract(tc.command)), gap2273Reading(want); g != w {
			t.Errorf("%q:\n got %s\nwant %s (the twin %q)", tc.command, g, w, tc.twin)
		}
	}
	// What the tools read from a file of names or patterns stays an unknown
	// flag, as at the parent, and so does an ambiguous prefix.
	for _, command := range []string{
		"wc --files0-from=" + f,
		"du --files0-from=" + f,
		"du -X " + f + " " + d,
		"diff --exclude-from=" + f + " " + d + " /home/u/proj/dst",
		"diff --new " + f + " " + g, // ambiguous: --new-file, --new-group-format, --new-line-format
	} {
		if !gap2273UnknownFlag(extract(command)) {
			t.Errorf("%q: no unknown, want the option left unknown", command)
		}
	}
	if !SummaryReader("wc") || !SummaryReader("md5sum") || !SummaryReader("cksum") {
		t.Error("SummaryReader lost a digest row")
	}
}
