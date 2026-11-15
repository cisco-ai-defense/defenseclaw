// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// rel-1-0-10 GAP-0891: a signed-out Hermes account is one unverified entry
// that is never read (GAP-0884), so its files may still name an old launch
// folder. Prune must not remove any superseded folder while such an entry is
// left; it removed both old folders here.
func TestHookImagePruneKeepsEverySupersededFolderOverAnUnverifiedAccountFile(t *testing.T) {
	now := time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)
	old := now.Add(-60 * 24 * time.Hour)
	f, names := threeReleases(t, [3]time.Time{old, old.Add(time.Hour), old.Add(2 * time.Hour)})
	const hermes = `C:\Users\dcw-std2\AppData\Local\hermes\config.yaml`
	report := pruneWindowsHookImages(f, hookImageTestBin, nil, windowsHookImagePrunePolicy{
		Scan: windowsHookImageConfigScan{Named: map[string][]string{}, Unverified: []windowsHookImageUnverifiedFile{{
			File: windowsHookImageConfigFile{Path: hermes, User: true, Home: `C:\Users\dcw-std2`, SID: skipTestSID},
			Err:  "signed out, Hermes home not resolvable while its registry hive is not loaded (HERMES_HOME may move it)",
		}}},
		Now: now,
	})
	if !report.OK || len(report.Removed) != 0 || len(report.Retained) != 2 {
		t.Fatalf("prune = %+v; nothing superseded may go while an account file is unverified", report)
	}
	for _, kept := range report.Retained {
		if kept.Why != "unverified_account_file:"+hermes {
			t.Fatalf("retained = %+v", report.Retained)
		}
	}
	for _, name := range names[:2] {
		if _, ok := f.get(winpath.EnterpriseHookImagesRoot(hookImageTestBin) + `\` + name); !ok {
			t.Fatalf("prune removed %s", name)
		}
	}
	if !strings.Contains(strings.Join(report.Notes, "\n"), "unverified_account_files: 1 account file(s)") {
		t.Fatalf("notes = %v", report.Notes)
	}
}
