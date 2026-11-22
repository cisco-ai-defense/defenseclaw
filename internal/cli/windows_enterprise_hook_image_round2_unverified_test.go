// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"io/fs"
	"strings"
	"testing"
)

// rel-1-0-10 GAP-0884: an account file the list could not vouch for (a
// signed-out account's Hermes home, an agent home moved out of the profile)
// is never looked at or read: it is unverified with the list's reason, and
// retire names it unreadable and stays pending.
func TestHookImageExpandNamesAnUnverifiedListEntry(t *testing.T) {
	const reason = "signed out, Hermes home not resolvable while its registry hive is not loaded (HERMES_HOME may move it): the account is signed out"
	viewed := false
	view := windowsHookImageAccountView(func(home, path string) (fs.FileInfo, []fs.DirEntry, error) {
		viewed = true
		return nil, nil, fs.ErrNotExist
	})
	entry := windowsHookImageConfigFile{Path: `C:\Users\dcw-std2\AppData\Local\hermes\config.yaml`, User: true, Home: `C:\Users\dcw-std2`, SID: skipTestSID, Unverified: reason}
	files, incomplete, unverified := expandWindowsHookImageConfigFiles([]windowsHookImageConfigFile{entry}, nil, nil, view)
	if viewed || len(files) != 0 || len(incomplete) != 0 || len(unverified) != 1 || unverified[0].Err != reason || unverified[0].File.SID != skipTestSID {
		t.Fatalf("viewed %t files %+v incomplete %v unverified %+v", viewed, files, incomplete, unverified)
	}
	r := newRetireFixture(t)
	steps := r.steps()
	steps.Scan = func() windowsHookImageConfigScan {
		return windowsHookImageConfigScan{Named: map[string][]string{}, Unverified: unverified}
	}
	report := retireWindowsHookImages(steps)
	if report.OK || report.Reason != windowsHookImageRetirePending || len(report.StillNamed) != 1 ||
		!report.StillNamed[0].Account || !report.StillNamed[0].Unreadable || !strings.Contains(report.StillNamed[0].Cause, "signed out, Hermes home not resolvable") {
		t.Fatalf("retire over a signed-out Hermes account = %+v", report)
	}
}
