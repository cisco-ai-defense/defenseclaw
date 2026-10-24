// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"
)

// GAP-0888: an installer engine ended from outside with no diagnostic is
// named, not reported as the raw exit code alone.
func TestWindowsEnterpriseInstallerExitFailureNamesAKilledEngine(t *testing.T) {
	killed := windowsEnterpriseInstallerExitFailure(4294967295).Error()
	if !strings.Contains(killed, "was ended before it reported a result") || !strings.Contains(killed, "4294967295") ||
		!strings.Contains(killed, windowsEnterpriseLifecycleLogPath) {
		t.Fatalf("killed engine = %q", killed)
	}
	other := windowsEnterpriseInstallerExitFailure(5).Error()
	if strings.Contains(other, "was ended") || !strings.Contains(other, "without a diagnostic") {
		t.Fatalf("other exit = %q", other)
	}
}

// GAP-0888: the LocalSystem purge's per_user_state_remaining error does not
// tell a LocalSystem run to run as LocalSystem, and says what a missing
// profile folder means.
func TestWindowsEnterpriseUserStateRemainingMessageForALocalSystemRun(t *testing.T) {
	got := windowsEnterpriseUserStateRemainingMessage(2, "alice, bob")
	if strings.Contains(got, "remove what stays as LocalSystem") || !strings.Contains(got, "ran as LocalSystem") ||
		!strings.Contains(got, "no longer exists has nothing left to remove") || !strings.HasSuffix(got, "Accounts: alice, bob") {
		t.Fatalf("message = %q", got)
	}
}
