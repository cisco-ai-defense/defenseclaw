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

// cowork-1-0-8 GAP-0080 review L4: an epoch is a random positive id, so two
// runs that start in one clock tick, or under a frozen clock, differ.
func TestNewEpochIsARandomPositiveID(t *testing.T) {
	seen := map[int64]bool{}
	for range 1000 {
		epoch := NewEpoch()
		if epoch <= 0 || seen[epoch] {
			t.Fatalf("epoch %d: want a positive id never drawn before", epoch)
		}
		seen[epoch] = true
	}
}
