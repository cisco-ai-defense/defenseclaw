// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"runtime"
	"strings"
	"testing"
)

// rel-1-0-10:GAP-2027: the statements of the longer syntax-tail reading of
// GAP-0745 took slots of the 128-statement cap of the 1.0.10 window reading,
// so this benign script (a syntax error, 20 long while loops, touch
// notes.txt) was TRUNCATED: an alert in default, permissive and managed, a
// block in strict and managed strict. T21f reads it whole and allows it in
// every tier.
func TestGAP2027ExtendedReadingsDoNotTruncateABenignScript(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fixture is POSIX shell text")
	}
	loop := "while :; do true; true; true; true; true; true; true; done\n)\n"
	command := ")\n" + strings.Repeat(loop, 20) + "touch notes.txt"
	for _, p := range gap0437Packs {
		t.Run(p.name, func(t *testing.T) {
			hook := gap0437Server(t, p, "claudecode", "action")
			if out := gap0437Hook(t, hook, t.TempDir(), p.name+"gap2027", command); out["action"] != "allow" {
				t.Errorf("%s: action %v, want allow as in T21f: %v", p.name, out["action"], out)
			}
		})
	}
}
