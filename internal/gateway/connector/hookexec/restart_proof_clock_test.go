// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookexec

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/proofclock/proofclocktest"
)

// The post-deadline proofs of a per-user call run on the proof clock
// (internal/proofclock). A test that wants a positive proof installs a clock
// it controls, so the proof ends on its result and never on the speed of the
// host; it does not widen the budget. These two checks keep the product
// budgets the tests rely on at the values that bound a real call.

// TestRestartProofBudgetsKeepTheirProductValues pins the budgets that bound
// how far a hook call may run past its deadline.
func TestRestartProofBudgetsKeepTheirProductValues(t *testing.T) {
	for _, tc := range []struct {
		name      string
		got, want time.Duration
	}{
		{"restartProofWait", restartProofWait, 250 * time.Millisecond},
		{"perUserRestartProofBudget", perUserRestartProofBudget, 300 * time.Millisecond},
		{"perUserPeerReadWait", perUserPeerReadWait, 500 * time.Millisecond},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %v, want %v", tc.name, tc.got, tc.want)
		}
	}
}

// requireRestartProofBudgets checks that a restart proof that ran on clock
// asked for its product budget and for nothing longer than the longest one.
func requireRestartProofBudgets(t *testing.T, clock *proofclocktest.Clock) {
	t.Helper()
	budget := false
	for _, d := range clock.Requested() {
		if d > perUserPeerReadWait {
			t.Errorf("the proof started a timer of %v, longer than any proof budget", d)
		}
		budget = budget || d == perUserRestartProofBudget
	}
	if !budget {
		t.Errorf("the proof never started its budget of %v (timers %v)", perUserRestartProofBudget, clock.Requested())
	}
}
