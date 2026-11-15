// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// TestHostScriptReadingPastTheParserDepthIsTruncated (rel-1-0-10:GAP-0478): a
// script psparse stops reading at its depth guard has no reading, and the
// reading says it was truncated at the depth instead of saying nothing.
func TestHostScriptReadingPastTheParserDepthIsTruncated(t *testing.T) {
	blocks := func(layers int) string {
		return strings.Repeat("& { ", layers) + "Get-Date" + strings.Repeat(" }", layers)
	}
	for _, layers := range []int{250, 320} {
		input := hookShellInput(t, "PowerShell", blocks(layers))
		reading := HostScriptReadings(input, Analyze(input), 0, false)
		if !reading.Caps.Has(bounded.Depth) {
			t.Fatalf("%d call blocks: caps %s, want the depth", layers, reading.Caps.Reason())
		}
	}
	// An unbalanced script is not resolved, which is not a truncation.
	input := hookShellInput(t, "PowerShell", "Write-Output a; & { Get-Date")
	if reading := HostScriptReadings(input, Analyze(input), 0, false); reading.Caps.Any() {
		t.Fatalf("an unbalanced script is truncated: %s", reading.Caps.Reason())
	}
}
