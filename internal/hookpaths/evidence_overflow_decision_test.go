// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

// A map that gives up its operands for the budget keeps the one fact that a
// protected target was found, in the incomplete header and in the unproven
// header alike, and carries it for no call that found none (GAP-0943).
func TestOverflowHeadersKeepTheProtectedTargetReadingOnlyWhenFound(t *testing.T) {
	cwd := "/work/proj"
	for _, found := range []bool{true, false} {
		for name, evidence := range map[string]string{
			"incomplete": incompleteEvidenceKeeping(cwd, found),
			"unproven":   unprovenEvidence(cwd, "trap", "/work/proj", found),
		} {
			targets, ok := Decode(evidence)
			if !ok {
				t.Fatalf("%s header (found=%t) does not decode", name, found)
			}
			if got := targets[ActionDecisionKey] == ProtectedTargetDecision; got != found {
				t.Errorf("%s header: protected-target reading = %t, want %t", name, got, found)
			}
			if targets[TruncatedKey] != "1" || targets[CWDKey] != cwd {
				t.Errorf("%s header lost its incomplete marker or cwd: %v", name, targets)
			}
		}
	}
}
