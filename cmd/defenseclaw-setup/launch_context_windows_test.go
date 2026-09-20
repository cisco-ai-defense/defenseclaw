// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import "testing"

func TestWindowsLaunchContextProbeAllowsNormalCurrentUser(t *testing.T) {
	facts, err := probeSetupLaunchContext()
	if err != nil {
		t.Fatal(err)
	}
	decision := decideSetupLaunchContext(facts)
	if decision.Reason != setupLaunchAllowed {
		// Service and session-zero CI runners are expected to exercise the pure
		// rejection matrix instead. A signed-in developer or hosted interactive
		// runner must pass this native integration check.
		t.Skipf("test process is intentionally outside a normal interactive user context: facts=%+v decision=%+v", facts, decision)
	}
	if facts.SessionID == 0 || facts.Elevated || facts.ServiceIdentity ||
		!facts.InteractiveToken || !facts.InteractiveWindowStation {
		t.Fatalf("allowed decision has inconsistent native facts: %+v", facts)
	}
}
