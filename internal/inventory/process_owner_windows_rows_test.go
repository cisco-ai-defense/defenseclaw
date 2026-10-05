// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"runtime"
	"testing"
	"time"
)

// GAP-1296: a per-user Windows install lists its own account's agents; the
// other accounts' rows (no user and no start time, since a standard account
// cannot open their processes) are left out.
func TestPerUserDiscoveryKeepsOnlyOwnWindowsRows(t *testing.T) {
	if runtime.GOOS == "windows" {
		account := currentWindowsAccount()
		if account == "" {
			t.Skip("current account cannot be resolved")
		}
		if owners := perUserProcessOwners(AIDiscoveryOptions{}); !owners[account] {
			t.Fatalf("perUserProcessOwners = %v, want %s", owners, account)
		}
	}
	old := processSnapshotSource
	t.Cleanup(func() { processSnapshotSource = old })
	started := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	processSnapshotSource = func() ([]processInfo, error) {
		return []processInfo{
			{PID: 456, PPID: 10468, Comm: "codex.exe", Windows: true},
			{PID: 1192, PPID: 900, Comm: "claude.exe", User: `DC-WIN2\dcw-fc2`, StartedAt: started, Windows: true},
		}, nil
	}
	svc := &ContinuousDiscoveryService{
		catalog: []AISignature{
			{ID: "claudecode", Name: "Claude Code", ProcessNames: []string{"claude"}},
			{ID: "codex", Name: "Codex", ProcessNames: []string{"codex"}},
		},
		processOwners: map[string]bool{`DC-WIN2\dcw-fc2`: true},
	}
	signals, err := svc.detectProcesses()
	if err != nil {
		t.Fatal(err)
	}
	if len(signals) != 1 || signals[0].Runtime == nil || signals[0].Runtime.PID != 1192 ||
		signals[0].Runtime.User != `DC-WIN2\dcw-fc2` || signals[0].Runtime.UptimeSec < 3500 {
		t.Fatalf("signals = %+v, want only this account's claude.exe (pid 1192) with its user and uptime", signals)
	}
}
