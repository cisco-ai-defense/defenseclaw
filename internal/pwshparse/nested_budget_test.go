// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package pwshparse

import (
	"strings"
	"testing"
	"time"
)

// TestNestedScanBudget: every level of a "$("$(... nest tokenizes the text
// inside it again, so without a bound the parse is quadratic (fixture row
// 39005, 100 KB: 3.2 s in the effects frontend, the legacy reader 26 ms). Past
// the nested-scan budget the parse is Unsupported (the consumer falls back to
// the legacy reader) and stays fast; a shallow nest is parsed in full.
func TestNestedScanBudget(t *testing.T) {
	// 15,000 levels stay under maxParseDepth: only the nested-scan budget declines them
	nest := "Write-Output " + strings.Repeat(`"$(`, 15000) + strings.Repeat(`)"`, 15000)
	if r := ParseTree(nest); !r.Unsupported {
		t.Error("15,000-level nest (45 KB): want Unsupported past the nested-scan budget")
	}
	bomb := "Write-Output " + strings.Repeat(`"$(`, 100000) + strings.Repeat(`)"`, 100000)
	st := time.Now()
	r := ParseTree(bomb)
	if el := time.Since(st); el > 2*time.Second {
		t.Errorf("500 KB nest parsed in %v, want a bounded parse", el)
	}
	if !r.Unsupported {
		t.Error("500 KB nest: want Unsupported")
	}
	shallow := "Write-Output " + strings.Repeat(`"$(`, 8) + "Remove-Item C:\\x" + strings.Repeat(`)"`, 8) + "; " + strings.Repeat("Get-Date; ", 400)
	if r := ParseTree(shallow); r.Unsupported {
		t.Error("8-level nest: want a full parse")
	}
}
