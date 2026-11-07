// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookexec

import (
	"testing"
	"time"
)

// unhurriedRestartProof lifts the post-deadline budgets of the restart
// proofs for one test that asserts a positive proof. Those budgets bound how
// long a real hook call may run past its deadline; the proof they bound reads
// every process of the account, so on a loaded host a test that shares them
// with the product measures the host, not the logic. The budgets themselves
// stay pinned by the tests that set their own value (a blocked start-lock
// look, a 5 ms restartProofWait). Call it before the test starts a proof, and
// only from a test that waits for every proof it starts.
func unhurriedRestartProof(t *testing.T) {
	t.Helper()
	wait, budget, read := restartProofWait, perUserRestartProofBudget, perUserPeerReadWait
	restartProofWait, perUserRestartProofBudget, perUserPeerReadWait = 30*time.Second, 30*time.Second, 5*time.Second
	t.Cleanup(func() {
		restartProofWait, perUserRestartProofBudget, perUserPeerReadWait = wait, budget, read
	})
}
