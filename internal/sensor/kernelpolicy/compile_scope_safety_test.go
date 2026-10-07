// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package kernelpolicy

import "testing"

func TestMultiUserControlsDoNotCrossMatchNativeBinaries(t *testing.T) {
	w := newWorld(t, baseTargets)
	roots := w.roots(nativeProc(4001, 1, 100, 1001, aliceClaudeNew), codexProc(5001, 1, 120, 1002))
	compiled := w.compile(Input{Controls: &Scope{Mode: PolicyEnforce, UIDs: []int{1001, 1002}}, Roots: roots.Roots})
	policy := policyOf(t, compiled, FamilyControls)
	if len(policy.Binaries) == 0 {
		t.Fatal("the selected user's native binary should remain an anchor")
	}
	binarySelectors := 0
	for _, hook := range selectorsOf(t, policy) {
		for _, selector := range hook {
			if len(selector.MatchBinaries) == 0 || selector.MatchActions[0].Action != "Override" {
				continue
			}
			binarySelectors++
			for _, arg := range selector.MatchArgs {
				if arg.Index == 2 && (len(arg.Values) != 1 || arg.Values[0] != "1001") {
					t.Fatalf("binary selector crosses enrolled uids: %+v", arg.Values)
				}
			}
		}
	}
	if binarySelectors == 0 || len(policy.PIDs) != 0 {
		t.Fatalf("enforcement must use only native binary selectors: %d selectors, pids %v", binarySelectors, policy.PIDs)
	}
}
