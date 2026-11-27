// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package effects

import "testing"

// TestGAP2214StdinDuplicateWithoutAPipeIsOpaqueCode: an interpreter with no
// script or -c operand whose standard input is a descriptor duplicate or a
// read-write open (<&3, 0<&3, <>) runs code we cannot see, as `sh < file`
// does, pipe or no pipe; so does source /dev/stdin. Each gives the opaque-code
// exec. A shell given a script or -c reads that instead, so the same redirect
// is data and gives none. Red at 78506d3a71 (CHK-RF-EFFECTS-R2 N1): without a
// pipe these gave only the plain exec of the interpreter.
func TestGAP2214StdinDuplicateWithoutAPipeIsOpaqueCode(t *testing.T) {
	o := Options{Flavor: FlavorPOSIX, Dialect: DialectPOSIX, Home: "/home/u", CWD: "/home/u/proj",
		Env: map[string]string{"HOME": "/home/u"}}
	opaque := func(command string) bool {
		r := Extract(Call{Surface: SurfaceShell, Tool: "shell", Command: command, Workdir: o.CWD}, o)
		for _, e := range r.Effects {
			if e.Kind != KindExec {
				continue
			}
			for _, reason := range e.Reasons {
				if reason.Code == ReasonOpaqueCode {
					return true
				}
			}
		}
		return false
	}
	for _, tc := range []struct {
		command string
		want    bool
	}{
		{"sh < in.txt", true}, // the GAP-0132 twin
		{"sh <&3", true},
		{"sh 0<&3", true},
		{"bash <> in.txt", true},
		{"python3 <&3", true},
		{"source /dev/stdin <&3", true},
		{". /dev/stdin 0<&3", true},
		{"sh run.sh <&3", false},
		{"sh -c true 0<&3", false},
		{"sh run.sh < in.txt", false},
	} {
		if got := opaque(tc.command); got != tc.want {
			t.Errorf("%q: opaque code = %t, want %t", tc.command, got, tc.want)
		}
	}
}
