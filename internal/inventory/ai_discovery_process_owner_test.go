// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package inventory

import (
	"testing"
	"time"
)

// GAP-1105/GAP-1194: a per-user install lists its own account's agents,
// not another account's newer process of the same agent.
func TestPerUserDiscoveryListsOnlyOwnAccountProcesses(t *testing.T) {
	name, uid := CurrentProcessOwner()
	if name == "" || uid == "" {
		t.Skip("current account cannot be resolved")
	}
	for _, opts := range []AIDiscoveryOptions{
		{ManagedEnterprise: true},
		{StandaloneEnterprise: true},
		{UserScanDir: "/var/lib/spool"},
	} {
		if owners := perUserProcessOwners(opts); owners != nil {
			t.Errorf("perUserProcessOwners(%+v) = %v, want nil (machine-wide)", opts, owners)
		}
	}
	if account := perUserAccount(AIDiscoveryOptions{SecureClient: true}); account.id != "" {
		t.Errorf("perUserAccount(Secure Client) = %+v, want none", account)
	}
	owners := perUserProcessOwners(AIDiscoveryOptions{})
	if !owners[name] || !owners[uid] {
		t.Fatalf("perUserProcessOwners = %v, want %s and %s", owners, name, uid)
	}

	old := processSnapshotSource
	t.Cleanup(func() { processSnapshotSource = old })
	started := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	processSnapshotSource = func() ([]processInfo, error) {
		return []processInfo{
			{PID: 64731, PPID: 1, Comm: "claude", User: name, StartedAt: started},
			{PID: 89492, PPID: 1, Comm: "claude", User: "dc-other-account", StartedAt: started.Add(30 * time.Minute)},
			{PID: 90001, PPID: 1, Comm: "codex", User: "dc-other-account", StartedAt: started},
		}, nil
	}
	svc := &ContinuousDiscoveryService{
		catalog: []AISignature{
			{ID: "claudecode", Name: "Claude Code", ProcessNames: []string{"claude"}},
			{ID: "codex", Name: "Codex", ProcessNames: []string{"codex"}},
		},
		processOwners: owners,
		account:       perUserAccount(AIDiscoveryOptions{}),
	}
	signals, _ := svc.scanSignals(t.Context(), "scan-per-user", nil, false, nil)
	if len(signals) != 1 || signals[0].Runtime == nil || signals[0].Runtime.PID != 64731 {
		t.Fatalf("signals = %+v, want only this account's claude (pid 64731)", signals)
	}
	// GAP-0016: the signal names the install's account, so its records carry
	// that account's identity.
	if signals[0].UserID != uid || signals[0].UserName == "" {
		t.Fatalf("signal account = %q/%q, want uid %s", signals[0].UserID, signals[0].UserName, uid)
	}
}
