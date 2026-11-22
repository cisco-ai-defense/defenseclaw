// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// gap1282Rows are the rel-1-0-10:GAP-1282 rows (review round 4 of
// s7/g1209fix: B01, B04, B16) in the spelling of the home C:\Users\Alice.
// Each source is a glob whose bracket the reader cannot translate exactly
// (a POSIX class, an expansion inside it); Bash expands each to config.yaml.
// The base reads as *, so the call is the unknown tier, as "$F" is (W03).
func gap1282Rows() []struct{ id, want, command string } {
	return []struct{ id, want, command string }{
		{"B01", "unknown", `mv -t ~/.defenseclaw config.yam[[:alpha:]]`},
		{"B16", "unknown", `mv -t ~/.defenseclaw config.yam[[:lower:]]`},
		{"B04", "unknown", `mv -t ~/.defenseclaw config.yam[$C]`},
	}
}

// gap1283Rows are the rel-1-0-10:GAP-1283 rows (review round 4 of
// s7/g1209fix: C01 to C07): a command that reads the state and moves or
// copies a source of unknown name into folders out of the state tree. No
// landing is a state entry, so the call stays allowed, as at rel and
// e1633b41c9, however many folders it names (C03 and C04 are controls).
func gap1283Rows() []struct{ id, want, command string } {
	return []struct{ id, want, command string }{
		{"C01", "allow", `cat ~/.defenseclaw/config.yaml; cp -t ~/b1 "$F"; cp -t ~/b2 "$F"; cp -t ~/b3 "$F"`},
		{"C02", "allow", `ls ~/.defenseclaw && cp -t ~/b1 "$1" && cp -t ~/b2 "$1" && cp -t ~/b3 "$1"`},
		{"C03", "allow", `cp -t ~/b1 "$F"; cp -t ~/b2 "$F"; cp -t ~/b3 "$F"`},
		{"C04", "allow", `cat ~/.defenseclaw/config.yaml; cp -t ~/b1 "$F"; cp -t ~/b2 "$F"`},
		{"C05", "allow", `grep -r x ~/.defenseclaw/policies; cp -t out1 *; cp -t out2 *; cp -t out3 *`},
		{"C06", "allow", `cp ~/.defenseclaw/config.yaml ~/b0/; cp -t ~/b1 "$F"; cp -t ~/b2 "$F"; cp -t ~/b3 "$F"`},
		{"C07", "allow", `cat ~/.defenseclaw/config.yaml; for f in *.log; do cp -t ~/b1 "$f"; cp -t ~/b2 "$f"; cp -t ~/b3 "$f"; done`},
	}
}

// TestGAP1282TargetDirectoryBracketSources pins rel-1-0-10:GAP-1282 on the
// reading the Windows hooks give a Bash or shell_command call of a drive
// home, on every OS. At 438e43f1e3 targetDirectoryBasePattern closed a
// bracket at its first ] in one literal and dropped a name path.Match
// refused, so these sources matched no state name and the calls were
// allowed (rel 8da6d97fc0 blocks them).
func TestGAP1282TargetDirectoryBracketSources(t *testing.T) {
	checkGAP1260Rows(t, "gap1282", gap1282Rows())
}

// TestGAP1283TargetDirectoryPlainFolders pins rel-1-0-10:GAP-1283. At
// 438e43f1e3 every landing of a source of unknown name counted toward the
// 64-form bound, and past it the state-naming command was the write: three
// plain folders (3 x 24 landings) blocked as tamper.detector_state_write.
func TestGAP1283TargetDirectoryPlainFolders(t *testing.T) {
	checkGAP1260Rows(t, "gap1283", gap1283Rows())
}
