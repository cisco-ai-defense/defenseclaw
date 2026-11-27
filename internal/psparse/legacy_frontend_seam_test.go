// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package psparse

import "testing"

// TestParseEffectsLegacyFrontendSeam: the reader choice of ParseEffects is a
// link-time/test seam, not an environment knob (GAP-1924). Unset, the port
// builds the Script, also when the gate runs it with the old PS_FRONTEND=psparse variable
// in the environment (that variable no longer exists); with the seam set, Parse does.
func TestParseEffectsLegacyFrontendSeam(t *testing.T) {
	src := `Remove-Item -Path C:\work\a.txt -Force`
	if _, port, err := ParseEffects(src, Options{Dialect: DialectUnknown}); err != nil || !port {
		t.Fatalf("default reader: want the port (port=true), got port=%v err=%v", port, err)
	}
	old := legacyFrontend
	legacyFrontend = "psparse"
	defer func() { legacyFrontend = old }()
	if _, port, err := ParseEffects(src, Options{Dialect: DialectUnknown}); err != nil || port {
		t.Fatalf("legacyFrontend seam: want Parse (port=false), got port=%v err=%v", port, err)
	}
}
