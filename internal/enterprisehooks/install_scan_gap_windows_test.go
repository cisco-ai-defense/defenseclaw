// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"testing"
)

// rel-1-0-10 GAP-0802: an enrolled account the cycle could not inspect in
// time is a scan gap (its code is recorded), so status judges it by the
// managed hook of the account, as it judges a home it could not list.
func TestWindowsManifestScanIncompleteEntriesAreScanGaps(t *testing.T) {
	const sid = "S-1-5-21-1-2-3-1001"
	subjects := map[string]WindowsManifestSubject{sid: {Home: `C:\Users\alice`, Connectors: []string{"claudecode", "codex"}}}
	for scanErr, want := range map[error]string{
		context.DeadlineExceeded: PrivateInstallSkippedTimedOut,
		context.Canceled:         PrivateInstallSkippedTimedOut,
		nil:                      PrivateInstallSkippedUnresolved,
	} {
		agents := WindowsManifestScanIncomplete(subjects, nil, nil, scanErr)
		if len(agents) != 2 {
			t.Fatalf("%v: entries = %+v, want one per connector", scanErr, agents)
		}
		for _, agent := range agents {
			if agent.SID != sid || agent.User != "alice" || agent.Skipped != want || !agent.InstallScanGap() ||
				agent.Code != UnprotectedCodeInstallScanIncomplete {
				t.Fatalf("%v: entry = %+v, want a %s scan gap", scanErr, agent, want)
			}
		}
	}
}
