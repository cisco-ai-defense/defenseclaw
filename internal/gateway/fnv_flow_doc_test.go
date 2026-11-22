// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"strings"
	"testing"
)

// The CHANGELOG entry for the tool-result check must not carry the figures
// of the void benchmark run (strict block 1,816 to 109, alert 4,062 to 192,
// default alert 255 to 115). Only the valid before/after pair may be quoted.
func TestFnvToolResultChangelogQuotesOnlyTheValidRun(t *testing.T) {
	raw, err := os.ReadFile("../../CHANGELOG.md")
	if err != nil {
		t.Fatal(err)
	}
	var entry string
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.Contains(line, "A tool's output never blocks") {
			entry = line
			break
		}
	}
	if entry == "" {
		t.Fatal("the tool-result CHANGELOG entry is missing")
	}
	for _, void := range []string{"255 to 115", "1,816", "4,062", "to 109", "to 192"} {
		if strings.Contains(entry, void) {
			t.Errorf("the entry carries the figure %q of the void run", void)
		}
	}
}
