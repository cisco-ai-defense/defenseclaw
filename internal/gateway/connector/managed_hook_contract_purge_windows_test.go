// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsManagedHookContractInteractiveUserSID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		sid  string
		want bool
	}{
		{name: "local or domain user", sid: "S-1-5-21-111-222-333-1001", want: true},
		{name: "Entra user", sid: "S-1-12-1-1111111111-2222222222-3333333333-4000000000", want: true},
		{name: "SYSTEM", sid: "S-1-5-18"},
		{name: "LocalService", sid: "S-1-5-19"},
		{name: "NetworkService", sid: "S-1-5-20"},
		{name: "Builtin Administrators", sid: "S-1-5-32-544"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sid, err := windows.StringToSid(test.sid)
			if err != nil {
				t.Fatalf("parse SID: %v", err)
			}
			if got := windowsManagedHookContractInteractiveUserSID(sid); got != test.want {
				t.Fatalf("interactive SID result = %t, want %t", got, test.want)
			}
		})
	}
}

func TestClearManagedHookContractLockEntryForOwnerPreservesPeers(t *testing.T) {
	if err := requireWindowsCodexMachineAdministrator(); err != nil {
		t.Skipf("managed purge requires an elevated Administrator or LocalSystem token: %v", err)
	}
	dataDir := filepath.Join(t.TempDir(), ".defenseclaw")
	ownerSID := windowsProcessUserSIDForTest(t).String()
	connectors := []string{"claudecode", "codex", "cursor"}
	for _, name := range connectors {
		if err := ReconcileManagedNativeHookRuntime(
			dataDir,
			"127.0.0.1:18970",
			name,
			"scoped-"+name+"-token",
		); err != nil {
			t.Fatalf("reconcile %s managed runtime: %v", name, err)
		}
		if err := SaveHookContractLockEntryForMode(dataDir, HookContractLockEntry{
			Connector:       name,
			RawAgentVersion: "old-" + name,
			ContractID:      name + "-hooks-v1",
			HookFailMode:    "closed",
		}, true); err != nil {
			t.Fatalf("save %s managed contract: %v", name, err)
		}
	}

	for index, name := range connectors {
		if err := ClearManagedHookContractLockEntryForOwner(
			dataDir,
			name,
			ownerSID,
		); err != nil {
			t.Fatalf("clear %s managed contract: %v", name, err)
		}
		lock, err := loadManagedHookContractLockForOwner(dataDir, ownerSID)
		if err != nil {
			t.Fatalf("load managed contract after clearing %s: %v", name, err)
		}
		if _, exists := lock.Connectors[name]; exists {
			t.Fatalf("%s contract survived purge", name)
		}
		for _, peer := range connectors[index+1:] {
			if _, exists := lock.Connectors[peer]; !exists {
				t.Fatalf("clearing %s removed peer %s", name, peer)
			}
		}
	}

	if err := SaveHookContractLockEntryForMode(dataDir, HookContractLockEntry{
		Connector:              "cursor",
		RawAgentVersion:        "3.19.19",
		NormalizedAgentVersion: "3.19.19",
		ContractID:             "cursor-hooks-v1",
		HookFailMode:           "closed",
	}, true); err != nil {
		t.Fatalf("write fresh Cursor contract after purge: %v", err)
	}
	lock, err := loadManagedHookContractLockForOwner(dataDir, ownerSID)
	if err != nil {
		t.Fatal(err)
	}
	if got := lock.Connectors["cursor"].RawAgentVersion; got != "3.19.19" {
		t.Fatalf("fresh Cursor contract version = %q, want 3.19.19", got)
	}
}
