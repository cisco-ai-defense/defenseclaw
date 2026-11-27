// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package shellparse

import (
	"slices"
	"strings"
	"testing"
)

// TestSyntaxTailCutBackLeavesBudgetForTheWindowReading pins the 1.0.10
// window after a long cut-back through many words of the failed statement.
func TestSyntaxTailCutBackLeavesBudgetForTheWindowReading(t *testing.T) {
	command := "echo prefix; ((" + strings.Repeat(" a +", 1200) + "\necho window-tail"
	tail, ok := readSyntaxTail(command)
	if !ok || !slices.Contains(tail.Statements, "echo window-tail") {
		t.Fatalf("ok=%t truncated=%q statements=%d: trailing window statement was not read",
			ok, tail.Truncated.Reason(), len(tail.Statements))
	}
}
