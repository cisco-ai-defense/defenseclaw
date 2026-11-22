// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"strings"
	"testing"
)

// GAP-0575 (GAP-0568 P4): doctor printed a check's summary raw, while
// verify cleans it; the group_forms row carries config values and a token
// group, so an ESC in one reached the terminal.
func TestGAP0575DoctorRowsAreCleaned(t *testing.T) {
	var b bytes.Buffer
	printSubstrateDoctor(&b, substrateDoctorReport{Checks: []substrateCheck{
		{ID: "group_forms", Status: doctorWarn, Summary: "profile eng matches \x1b[2Jgroup names", Fix: "write \x1b]0;x\x07them"},
	}})
	if strings.ContainsAny(b.String(), "\x1b\x07") {
		t.Errorf("doctor printed control characters: %q", b.String())
	}
}
