// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// GAP-1109 evidence: orphan profiles whose SID-to-account lookup never
// answers do not hold the walk. Each lookup is bounded and the cycle's
// lookups share one budget, so 37 orphans named in exclude_users are
// excluded by their folder names within that budget.
func TestWindowsEnumerateBoundsBlockedLookupsOfOrphanProfiles(t *testing.T) {
	stubMachineWinGet(t, nil)
	stubActiveSessions(t, map[string][]string{})
	oldDomain := windowsMachineAccountDomainSID
	oldTimeout, oldBudget := windowsEnrollmentLookupTimeout, windowsEnrollmentLookupBudget
	t.Cleanup(func() {
		windowsMachineAccountDomainSID = oldDomain
		windowsEnrollmentLookupTimeout, windowsEnrollmentLookupBudget = oldTimeout, oldBudget
	})
	windowsMachineAccountDomainSID = func() (string, error) { return testMachineDomainSID, nil }
	windowsEnrollmentLookupTimeout, windowsEnrollmentLookupBudget = 50*time.Millisecond, 250*time.Millisecond
	root := t.TempDir()
	homes := map[string]string{}
	var names []string
	for i := 0; i < 37; i++ {
		name := fmt.Sprintf("dcw-orphan%02d", i)
		home := filepath.Join(root, name)
		if err := os.Mkdir(home, 0o700); err != nil {
			t.Fatal(err)
		}
		// Distinct from every other test's SIDs: a lookup the gate still
		// holds fails at once for its SID in later tests.
		homes[fmt.Sprintf("%s-%d", testMachineDomainSID, 7101+i)] = home
		names = append(names, name)
	}
	injectWindowsProfileList(t, homes)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	windowsEnrollmentLookupAccountSID = func(string) (string, string, error) {
		<-release
		return "", "", fmt.Errorf("released")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	started := time.Now()
	excluded := 0
	if _, err := EnumerateWindows(ctx, standaloneEnumeratorConfig("codex"), EnumerateOptions{
		ExcludeUsers:   names,
		ReportExcluded: func(ManifestTarget) { excluded++ },
	}); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Fatalf("37 orphan profiles with blocked lookups took %s", elapsed)
	}
	if excluded != 37 {
		t.Fatalf("excluded %d orphan profiles, want 37", excluded)
	}
}
