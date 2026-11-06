// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
package gateway

import "testing"

// The round-five oracle includes every round-four probe row and records the
// ratified Possible warnings and ordinary-link readings. Keep the round-four
// entry points exercising their original fixtures against that same verdict.
func rv4AssertCells(t *testing.T, suite, id string, cells []string) {
	t.Helper()
	if suite == "par" {
		suite = "parity"
	}
	rv5AssertCells(t, suite+"/"+id, cells)
}
