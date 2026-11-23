// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package psparse

import "testing"

// TestGAP1984BlankDecodedMarksTheNewReading (rel-1-0-10:GAP-1984, DET111
// ruling 2): an -EncodedCommand body read only past the tab, CR and LF
// blanks of its quoted value (GAP-1199, a reading 1.0.10 did not have) is
// marked BlankDecoded; the static word 1.0.10 read is not. The body is the
// same script either way.
func TestGAP1984BlankDecodedMarksTheNewReading(t *testing.T) {
	script := `Get-ChildItem .`
	ns, ok := firstHostNested("pwsh -enc "+r6enc(script), DialectPwsh7)
	if !ok || !ns.Static || ns.Text != script || ns.BlankDecoded {
		t.Errorf("static word: want Static %q, not BlankDecoded; got ok=%v %+v", script, ok, ns)
	}
	for _, argv := range gap1199BlankRows(script) {
		ns, ok := firstHostNested(hostShapeSource("pwsh", argv), DialectPwsh7)
		if !ok || !ns.Static || ns.Text != script || !ns.BlankDecoded {
			t.Errorf("argv=%q: want Static %q and BlankDecoded; got ok=%v %+v", argv, script, ok, ns)
		}
	}
}
