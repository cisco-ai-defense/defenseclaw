// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

// String text that no string of the program can run is data in every binary
// that resolves hook write evidence. The mask used to be wired in from the
// guardrail package init, so the slim defenseclaw-hook, which does not link
// the guardrail, reported this program as an unproven protected write (W1
// review P1).
func TestInertPythonStringTextIsDataWithoutTheGuardrail(t *testing.T) {
	code := `p = Path.home()/".ssh"/"authorized_keys"; print(f"p.write_text(42)")`
	home := t.TempDir()
	if got, unproven := unprovenInterpreterCode(code, "python3", home, home, true); unproven || got != "" {
		t.Fatalf("masked scan = %q, %v; want no unproven write", got, unproven)
	}
	if got, unproven := unprovenInterpreterCode(code, "python3", home, home, false); !unproven {
		t.Fatalf("unmasked scan = %q, %v; want the interpreter path (the mask is what proves it inert)", got, unproven)
	}
}
