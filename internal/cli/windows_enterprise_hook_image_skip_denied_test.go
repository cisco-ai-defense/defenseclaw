// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"
)

// rel-1-0-10 GAP-0907 (see windows_enterprise_hook_image_skip_denied_refuse_test.go):
// LocalSystem, or a profile with a real hold, can still be skipped, and
// status as Administrator does not call a profile it was denied not retired.

func TestHookImageRetireAcceptsTheSkipAsLocalSystemOrWithARealHold(t *testing.T) {
	scan := deniedScan(t)
	for _, file := range scan.Unverified {
		if !file.Denied {
			t.Fatalf("an access-denied account file is not marked denied: %+v", file)
		}
	}
	// LocalSystem was denied too: the account set that access list itself.
	s := newSkipFixture(t)
	steps := s.skipSteps(skipTestSID)
	steps.Scan = func() windowsHookImageConfigScan { return scan }
	steps.CallerSystem = func() bool { return true }
	if report := retireWindowsHookImages(steps); !report.OK || len(report.SkippedProfiles) != 1 || len(s.audits) != 1 {
		t.Fatalf("a LocalSystem skip of a profile it is denied = %+v", report)
	}
	// An Administrator skip of a profile that also has a file it could
	// not read for another reason (here a timeout) is accepted.
	timeout := scan
	timeout.Unverified = append([]windowsHookImageUnverifiedFile{{
		File: windowsHookImageConfigFile{Path: `C:\Users\dcw-std2\.kiro\agents\defenseclaw.json`, User: true, Home: `C:\Users\dcw-std2`, SID: skipTestSID},
		Err:  errWindowsHookImageScanTimeout.Error(),
	}}, scan.Unverified...)
	s = newSkipFixture(t)
	steps = s.skipSteps(skipTestSID)
	steps.Scan = func() windowsHookImageConfigScan { return timeout }
	if report := retireWindowsHookImages(steps); !report.OK || len(report.SkippedProfiles) != 1 {
		t.Fatalf("an Administrator skip of a profile with a timed-out file = %+v", report)
	}
}

func TestHookImageStatusDoesNotListAProfileTheCallerWasDeniedAsNotRetired(t *testing.T) {
	marker, _ := json.Marshal(windowsHookImageRetireMarker{SchemaVersion: 1, SkippedProfiles: []windowsHookImageSkippedProfile{
		{SID: skipTestSID, Account: `HOST\dcw-std2`, Home: `C:\Users\dcw-std2`, SkippedBy: `HOST\admin (S-1-5-21-1-2-3-500)`, SkippedAt: "2026-11-15T16:20:44Z",
			Files: []windowsHookImageNamedFile{{File: deniedCodexFile, Folder: windowsHookImageUnknownFolder, Account: true, Unreadable: true}}},
	}})
	read := func(file windowsHookImageConfigFile) ([]byte, error) {
		return nil, fmt.Errorf("open %s: %w", file.Path, fs.ErrPermission)
	}
	issues := windowsHookImageSkippedProfileIssues(marker, hookImageTestBin, read, windowsHookImageAccessDenied)
	if len(issues) != 1 || issues[0].Code != "hook_image_profile_unverified" || !strings.Contains(issues[0].Text, "LocalSystem") ||
		strings.Contains(issues[0].Text, "is not retired") {
		t.Fatalf("status as Administrator over a profile it is denied = %+v, want hook_image_profile_unverified", issues)
	}
	// As LocalSystem (no caller denial), a file it cannot read keeps the
	// profile listed as not retired.
	issues = windowsHookImageSkippedProfileIssues(marker, hookImageTestBin, read, nil)
	if len(issues) != 1 || issues[0].Code != "hook_image_profile_not_retired" {
		t.Fatalf("status as LocalSystem over an unreadable file = %+v", issues)
	}
	if windowsHookImageAccessDenied(errors.New("some other failure")) {
		t.Fatal("a plain error counts as access denied")
	}
}
