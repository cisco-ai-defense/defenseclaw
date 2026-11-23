// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"strings"
	"testing"
)

// fnvShellGaps keys the already frozen review tables to the S7 effects gaps they
// prove (rel-1-0-10 GAP-0183..GAP-0186, GAP-0197 and GAP-0132..GAP-0137). The
// rows run through checkRow, so each one still needs its frozen verdict and its
// real-target invariant; this test only names which rows belong to which gap and
// fails if a named row is removed. ids match a row id exactly or up to its first
// space; prefixes match a family of rows.
var fnvShellGaps = []struct {
	gap      string
	ids      []string
	prefixes []string
}{
	// round-8 regression: eval/source body in a && / || tail drops the narrowed cwd
	{gap: "GAP-0183", ids: []string{"rv8-C08", "rv8-C24", "rv8-C25", "rv8-C09", "rv8-C10", "rv8-C23", "rv9-N10", "rv9-N10a", "rv9-N10h"}, prefixes: []string{"rv9-N"}},
	// child HOME / export attributes
	{gap: "GAP-0184", ids: []string{"rv8-E05", "rv8-E06", "rv8-E07", "rv8-E08", "rv8-E09", "rv8-E10", "rv8-E11", "rv8-E16", "rv8-E17", "rv8-E20", "rv9-X05", "rv9-X09", "rv9-X10", "rv9-X11", "rv9-X12", "rv9-R01", "rv9-R02", "rv9-R04", "rv9-R05"}, prefixes: []string{"rv9-X"}},
	// program table accounts only what it parses
	{gap: "GAP-0185", ids: []string{"rv8-T01", "rv8-T02", "rv8-T03", "rv8-T04", "rv8-T05", "rv8-T06", "rv8-T07", "rv8-T08", "rv8-T09", "rv8-T10", "rv8-T11", "rv8-T21", "rv8-T24", "rv9-G01", "rv9-G02", "rv9-G03", "rv9-A01", "rv9-A02", "rv9-A03", "rv9-A09", "rv9-U01", "rv9-U04", "rv9-R03"}, prefixes: []string{"rv9-G", "rv9-A", "rv9-U"}},
	// cp -tDIR fused value
	{gap: "GAP-0186", ids: []string{"rv8-T19"}},
	// name operands evaluate an array subscript
	{gap: "GAP-0197", ids: []string{"rv9-I08", "rv9-I09", "rv9-I10", "rv9-I07", "rv9-I13"}},
	// review 7: bare cmd/sh/bash reading its script from stdin
	{gap: "GAP-0132", ids: []string{"rv7-K6", "rv8-S01", "rv8-S02", "rv8-S03", "rv8-S04", "rv8-S05"}, prefixes: []string{"rv7-C"}},
	// review 7: failed cd keeps the old cwd
	{gap: "GAP-0133", ids: []string{"rv7-B01", "rv7-B02", "rv7-B04", "rv7-B05", "rv7-B07", "rv7-E03", "rv7-E04", "rv8-W05", "rv8-W06", "rv8-W18"}, prefixes: []string{"rv7-B"}},
	// review 7: HOME/env passed into a child process
	{gap: "GAP-0134", ids: []string{"rv7-E01", "rv7-E02", "rv7-E09", "rv7-E10"}, prefixes: []string{"rv8-E"}},
	// review 7: cwd-moving wrappers
	{gap: "GAP-0135", ids: []string{"rv7-E05", "rv7-E06", "rv7-E07", "rv8-W01", "rv8-W03", "rv8-W04", "rv8-W07", "rv8-W09"}, prefixes: []string{"rv7-G", "rv8-W"}},
	// review 7: PowerShell function that shadows Set-Location
	{gap: "GAP-0136", ids: []string{"rv7-B48", "rv7-E08"}},
}

func fnvAllRows() []rv7case {
	var all []rv7case
	for _, set := range [][]rv7case{rv7cases, rv7bcases, rv7ccases, rv7ecases, rv8cases, rv9cases, rv9mcases} {
		all = append(all, set...)
	}
	return all
}

// fnvJudge judges one frozen row; "/nowrite" is a control that writes nothing
// protected, so only its frozen verdict is checked (as TestReview9ProbeTable does).
func fnvJudge(t *testing.T, c rv7case) {
	t.Helper()
	real := c.real
	if real == "/nowrite" {
		real = ""
	}
	checkRow(t, c.id, c.o, Call{Surface: SurfaceShell, Command: c.cmd, Workdir: c.wd}, real)
}

func TestFNVShellGapRows(t *testing.T) {
	all := fnvAllRows()
	for _, g := range fnvShellGaps {
		t.Run(g.gap, func(t *testing.T) {
			ran := map[string]bool{}
			for _, id := range g.ids {
				found := false
				for _, c := range all {
					if c.id == id || strings.HasPrefix(c.id, id+" ") {
						found = true
						ran[c.id] = true
						fnvJudge(t, c)
					}
				}
				if !found {
					t.Errorf("%s: row %s is gone from the frozen tables", g.gap, id)
				}
			}
			for _, p := range g.prefixes {
				n := 0
				for _, c := range all {
					if strings.HasPrefix(c.id, p) {
						n++
						if !ran[c.id] {
							ran[c.id] = true
							fnvJudge(t, c)
						}
					}
				}
				if n == 0 {
					t.Errorf("%s: no row with prefix %s", g.gap, p)
				}
			}
			t.Logf("%s: %d rows judged", g.gap, len(ran))
		})
	}
}

// GAP-0186: the fused -tDIR value of cp, mv and install is a KNOWN write at
// DIR/name, as for the spaced -t form, so an exact-file rule sees it.
func TestFNVShellFusedTargetDirectory(t *testing.T) {
	for _, cmd := range []string{
		"cp -t/home/u/.ssh authorized_keys",
		"cp -pt/home/u/.ssh authorized_keys",
		"cp -t /home/u/.ssh authorized_keys",
		"mv -t/home/u/.ssh authorized_keys",
		"install -t/home/u/.ssh authorized_keys",
		"install -m600 -t/home/u/.ssh authorized_keys",
		"cp --target-directory=/home/u/.ssh authorized_keys",
	} {
		t.Run(cmd, func(t *testing.T) {
			r := Extract(Call{Surface: SurfaceShell, Command: cmd}, raLin)
			if !r.FullyKnown() {
				t.Fatalf("not fully known\n%s", fmtRes(r))
			}
			for _, e := range r.Effects {
				if isMutation(e.Kind) && e.TargetState == TargetStateKnown && e.Target.Type == TargetPath && e.Target.Key() == rlAK {
					return
				}
			}
			t.Fatalf("no KNOWN mutation at %s\n%s", rlAK, fmtRes(r))
		})
	}
}
