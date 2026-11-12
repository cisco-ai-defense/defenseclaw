// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package connector

import "testing"

// heldProofHookPostForHookTests is hook-post built so that its restart proofs
// never spend a budget on a timer (internal/proofclock heldTimersBake): the
// proof ends on its own result, not on the speed of the host.
var heldProofHookPostForHookTests hookPostBuild

// installHeldProofHookPostForHookTest installs hook-post with its proof
// timers held, for a test whose positive outcome is a restart proof.
func installHeldProofHookPostForHookTest(t *testing.T, home string) {
	t.Helper()
	installHookPostBuild(t, home, &heldProofHookPostForHookTests,
		"-ldflags", "-X github.com/defenseclaw/defenseclaw/internal/proofclock.heldTimersBake=1")
}
