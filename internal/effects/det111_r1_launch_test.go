// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects_test

import (
	"strings"
	"testing"
)

// det111LaunchPending are launcher rows the IR does not lower yet, with the
// lane that closes each. A pending row that starts to pass fails the test.
var det111LaunchPending = map[string]string{}

// TestDET111R1LaunchTable is the fail-before table of the PowerShell launcher
// rows routed to S3-R1 (DET111 ruling 22:32Z: GAP-1557 -wd and positional
// script, GAP-1142 pwsh -Command on Linux and macOS), copied verbatim from the
// DET111 gap corpus C (lanes/s3r1c copy_launch_v1.py): a seed or variant row
// must reach a protected set, a benign row must not.
func TestDET111R1LaunchTable(t *testing.T) {
	cases := loadDET111CasesFile(t, "testdata/det111_r1_launch.cases.jsonl")
	for _, c := range cases {
		f := det111Collect(c)
		var ok bool
		switch c.role() {
		case "seed", "variant":
			ok = f.reach
		case "benign":
			ok = !f.reach
		default:
			continue
		}
		why, pending := det111LaunchPending[c.ID]
		switch {
		case pending && ok:
			t.Errorf("%s passes now: remove it from det111LaunchPending (%s)", c.ID, why)
		case !pending && !ok:
			_, _, lines := det111Run(c)
			t.Errorf("%s (%s): wrong protected reach:\n  %s", c.ID, c.role(), strings.Join(lines, "\n  "))
		}
	}
	if len(cases) < 12 {
		t.Fatalf("only %d launcher rows: the table lost rows", len(cases))
	}
}
