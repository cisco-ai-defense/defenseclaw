// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// GAP-1109: the walk tells its caller which profile it inspects, so an
// enumerate --once that gives up names the profile it waited on.
func TestWindowsEnumerateProgressNamesEachProfile(t *testing.T) {
	stubMachineWinGet(t, nil)
	stubActiveSessions(t, map[string][]string{})
	oldDomain := windowsMachineAccountDomainSID
	t.Cleanup(func() { windowsMachineAccountDomainSID = oldDomain })
	windowsMachineAccountDomainSID = func() (string, error) { return testMachineDomainSID, nil }
	home := codexProfile(t, "0.150.0")
	injectWindowsProfileList(t, map[string]string{testDeletedLocalSID: home})
	windowsEnrollmentLookupAccountSID = func(string) (string, string, error) { return "", "", windows.ERROR_NONE_MAPPED }
	ctx, cancel := context.WithTimeout(context.Background(), 9*time.Second)
	defer cancel()
	var steps []string
	if _, err := EnumerateWindows(ctx, standaloneEnumeratorConfig("codex"), EnumerateOptions{
		ExcludeUsers:   []string{testDeletedLocalSID},
		ReportExcluded: func(ManifestTarget) {},
		Progress:       func(step string) { steps = append(steps, step) },
	}); err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("inspecting the profile %s (%s), 1 of 1", filepath.Clean(home), testDeletedLocalSID)
	if !slices.Contains(steps, want) {
		t.Fatalf("progress = %q, want %q", steps, want)
	}
}
