// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
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

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-1733 review 2: the enumerator's new-row skip read "first adoption" from
// the existing manifest rows. An adopted account whose rows were all dropped
// (the user moved its agent aside) had no row left, so once the user planted
// the per-user install entry in its managed folder and restored the agent, its
// new row was skipped and the account was left unprotected. An account the
// guardian protected (EnumerateOptions.Enrolled) is still adopted: its row is
// written and the guardian reports the entry as tamper. The never-protected
// account is still skipped.
func TestEnumerateWindowsStandaloneKeepsANewRowOfAnEnrolledAccount(t *testing.T) {
	if !windowsTestRunsAsLocalSystem(t) && !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated Administrator to build the per-user install folder")
	}
	t.Setenv(managed.TrustStrictAncestorsEnv, "")
	stubMachineWinGet(t, nil)
	domain := fmt.Sprintf("S-1-5-21-1733%06d-%d-%d", os.Getpid()%1000000, time.Now().UnixNano()%1000000000, 1735)
	perUser := newGAP1733PerUserAccount(t, domain+"-1001")
	enrolledAccount := newGAP1733PerUserAccount(t, domain+"-1002")
	for _, account := range []gap1733Account{perUser, enrolledAccount} {
		writeWindowsAgentPackageJSON(t, filepath.Join(account.home, "AppData", "Local", "Programs", "cursor", "resources", "app"), "2.5.0")
	}
	perUserSID, enrolledSID := perUser.sid.String(), enrolledAccount.sid.String()
	injectWindowsProfileList(t, map[string]string{
		perUserSID:  perUser.home,
		enrolledSID: enrolledAccount.home,
	})
	manifest, err := EnumerateWindows(context.Background(), standaloneEnumeratorConfig("cursor"), EnumerateOptions{
		Enrolled: func(sid string) bool { return sid == enrolledSID },
	})
	if err != nil {
		t.Fatalf("EnumerateWindows: %v", err)
	}
	rows := map[string]bool{}
	for _, target := range manifest.Targets {
		if target.Connector == "cursor" {
			rows[target.SID] = true
		}
	}
	if !rows[enrolledSID] {
		t.Fatalf("the enrolled account with no manifest row was skipped as a first adoption; targets %+v", manifest.Targets)
	}
	if rows[perUserSID] {
		t.Fatalf("the never-protected account with a per-user install got a row; targets %+v", manifest.Targets)
	}
}
