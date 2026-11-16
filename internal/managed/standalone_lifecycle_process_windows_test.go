// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package managed

import "testing"

// A process that runs a standalone lifecycle action without a service pin and
// outside the install root (Setup's staged CLI) still refuses an in-place
// repair of a managed file or folder another account can write (GAP-0651);
// an unmarked process outside the scope keeps the Secure Client rules.
func TestMarkedLifecycleProcessRefusesContentDriftWithoutAPin(t *testing.T) {
	previousScope := windowsStandaloneTrustScope
	previousMark := standaloneLifecycleProcess.Load()
	t.Cleanup(func() {
		windowsStandaloneTrustScope = previousScope
		standaloneLifecycleProcess.Store(previousMark)
	})
	windowsStandaloneTrustScope = func() bool { return false }
	standaloneLifecycleProcess.Store(false)
	if StandaloneRefusesContentDrift() {
		t.Fatal("an unpinned process outside the install root refused content drift without being marked")
	}
	MarkStandaloneLifecycleProcess()
	if !StandaloneRefusesContentDrift() {
		t.Fatal("a marked standalone lifecycle process did not refuse content drift")
	}
	if windowsStandaloneTrustScope() {
		t.Fatal("marking the process widened the trust scope; it must only widen the content-drift refusal")
	}
}
