// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"strings"
	"testing"
)

// rel-1-0-10 GAP-0413: the GAP-0171 numbers in the CHANGELOG come from the
// valid before/after pair (tr2-rel to tr2-head), not from the void run s7tr-F.
// The figures of the void run (strict block 1,816 to 109, alert 4,062 to 192,
// default alert 255 to 115) must not return.
func TestFnvToolResultChangelogQuotesOnlyTheValidRun(t *testing.T) {
	raw, err := os.ReadFile("../../CHANGELOG.md")
	if err != nil {
		t.Fatal(err)
	}
	var entry string
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.Contains(line, "GAP-0171") && strings.Contains(line, "A tool's output never blocks") {
			entry = line
			break
		}
	}
	if entry == "" {
		t.Fatal("the GAP-0171 CHANGELOG entry is missing")
	}
	for _, want := range []string{"77 to 0", "255 to 122", "1,817 to 115", "4,063 to 198", "116 to 117", "124 to 0", "0.226 to 0.598"} {
		if !strings.Contains(entry, want) {
			t.Errorf("the entry does not carry the valid figure %q", want)
		}
	}
	for _, void := range []string{"255 to 115", "1,816", "4,062", "to 109", "to 192"} {
		if strings.Contains(entry, void) {
			t.Errorf("the entry carries the figure %q of the void run", void)
		}
	}
}
