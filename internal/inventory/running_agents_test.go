// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import "testing"

func TestRunningWindowsAgentProcessesKeepsOwnerSIDWithoutAccountName(t *testing.T) {
	previous := processSnapshotSource
	t.Cleanup(func() { processSnapshotSource = previous })
	const ownerSID = "S-1-5-21-1-2-3-1001"
	processSnapshotSource = func() ([]processInfo, error) {
		return []processInfo{{
			PID: 14, Comm: "codex.exe", Windows: true,
			SessionOwnerID: ownerSID,
		}}, nil
	}

	got, err := RunningWindowsAgentProcesses()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].PID != 14 || got[0].Connector != "codex" || got[0].User != "" || got[0].OwnerSID != ownerSID {
		t.Fatalf("running agent lost its snapshot owner SID: %+v", got)
	}
}
