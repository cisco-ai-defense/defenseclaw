// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestManagedHookContractEntryBindsExactWindowsGatewayScope(t *testing.T) {
	t.Setenv(WindowsGatewayServiceNameEnv, "DefenseClawGateway-ScopeA")
	entry, err := NewHookContractLockEntryForMode(
		SetupOpts{ManagedEnterprise: true, AgentVersion: "2.1.240"},
		NewClaudeCodeConnector(),
		"same-build",
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	if entry.ManagedGatewayServiceName != "DefenseClawGateway-ScopeA" {
		t.Fatalf("managed gateway binding = %q", entry.ManagedGatewayServiceName)
	}

	t.Setenv(WindowsGatewayServiceNameEnv, "")
	if _, err := NewHookContractLockEntryForMode(
		SetupOpts{ManagedEnterprise: true, AgentVersion: "2.1.240"},
		NewClaudeCodeConnector(),
		"same-build",
		true,
	); err == nil || !strings.Contains(err.Error(), "gateway service identity") {
		t.Fatalf("missing managed gateway binding error = %v", err)
	}
}

func TestWindowsManagedHookContractGatewayBindingRequiresExactCurrentService(t *testing.T) {
	t.Setenv(WindowsGatewayServiceNameEnv, "DefenseClawGateway-ScopeA")
	for _, test := range []struct {
		name    string
		service string
		wantErr bool
	}{
		{name: "exact", service: "DefenseClawGateway-ScopeA"},
		{name: "same SCM identity casing", service: "defenseclawgateway-scopea"},
		{name: "missing legacy binding", wantErr: true},
		{name: "foreign scope", service: "DefenseClawGateway-ScopeB", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateWindowsManagedHookContractGatewayServiceBinding(
				HookContractLockEntry{ManagedGatewayServiceName: test.service},
			)
			if (err != nil) != test.wantErr {
				t.Fatalf("gateway binding error = %v, wantErr %t", err, test.wantErr)
			}
		})
	}
}

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

func TestManagedHookContractCleanupClaimIgnoresGlobalTimestampAndRejectsReplacement(t *testing.T) {
	if err := requireWindowsCodexMachineAdministrator(); err != nil {
		t.Skipf("managed purge requires an elevated Administrator or LocalSystem token: %v", err)
	}
	dataDir := filepath.Join(t.TempDir(), ".defenseclaw")
	ownerSID := windowsProcessUserSIDForTest(t).String()
	if err := ReconcileManagedNativeHookRuntime(
		dataDir,
		"127.0.0.1:18970",
		"codex",
		"scoped-old-token",
	); err != nil {
		t.Fatal(err)
	}
	entry := HookContractLockEntry{
		Connector:                 "codex",
		RawAgentVersion:           "old-codex",
		ContractID:                "codex-hooks-v1",
		HookFailMode:              "closed",
		ManagedGatewayServiceName: "DefenseClawGateway-ScopeA",
	}
	if err := SaveHookContractLockEntryForMode(dataDir, entry, true); err != nil {
		t.Fatal(err)
	}
	claim, err := CaptureManagedHookContractCleanupClaimForOwner(
		dataDir,
		"codex",
		ownerSID,
		"DefenseClawGateway-ScopeA",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !claim.EntryPresent || !strings.HasPrefix(claim.EntrySHA256, "sha256:") {
		t.Fatalf("invalid cleanup claim: %+v", claim)
	}

	// A peer write may advance only the lock-global timestamp. The CAS is
	// connector-scoped, so that harmless shared mutation must not invalidate
	// the retired Codex claim.
	lock, err := loadManagedHookContractLockForOwner(dataDir, ownerSID)
	if err != nil {
		t.Fatal(err)
	}
	lock.UpdatedAt = nextHookContractTimestamp(time.Now(), lock.UpdatedAt)
	body, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	target, err := windows.StringToSid(ownerSID)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeManagedTargetRuntimeFileForTarget(
		filepath.Join(dataDir, hookContractLockFile),
		append(body, '\n'),
		true,
		target,
	); err != nil {
		t.Fatal(err)
	}
	result, err := ApplyManagedHookContractCleanupClaimForOwner(claim)
	if err != nil {
		t.Fatalf("apply claim after global timestamp change: %v", err)
	}
	if !result.Removed || result.AlreadyAbsent {
		t.Fatalf("cleanup result = %+v", result)
	}

	if err := SaveHookContractLockEntryForMode(dataDir, HookContractLockEntry{
		Connector:                 "codex",
		RawAgentVersion:           "replacement-codex",
		ContractID:                "codex-hooks-v2",
		HookFailMode:              "closed",
		ManagedGatewayServiceName: "DefenseClawGateway-ScopeB",
	}, true); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyManagedHookContractCleanupClaimForOwner(claim); err == nil ||
		!strings.Contains(err.Error(), "replacement connector entry") {
		t.Fatalf("replacement CAS error = %v", err)
	}
	stored, err := loadManagedHookContractLockForOwner(dataDir, ownerSID)
	if err != nil {
		t.Fatal(err)
	}
	if got := stored.Connectors["codex"].RawAgentVersion; got != "replacement-codex" {
		t.Fatalf("replacement entry changed to %q", got)
	}
}

func TestDelayedPurgePreservesSameContractPublishedByNewGatewayScope(t *testing.T) {
	if err := requireWindowsCodexMachineAdministrator(); err != nil {
		t.Skipf("managed purge requires an elevated Administrator or LocalSystem token: %v", err)
	}
	dataDir := filepath.Join(t.TempDir(), ".defenseclaw")
	ownerSID := windowsProcessUserSIDForTest(t).String()
	if err := ReconcileManagedNativeHookRuntime(
		dataDir,
		"127.0.0.1:18970",
		"codex",
		"same-scoped-token-shape",
	); err != nil {
		t.Fatal(err)
	}
	entry := HookContractLockEntry{
		Connector:                 "codex",
		RawAgentVersion:           "same-codex",
		ContractID:                "codex-hooks-v1",
		DefenseClawVersion:        "same-build",
		HookFailMode:              "closed",
		ManagedGatewayServiceName: "DefenseClawGateway-ScopeA",
	}
	if err := SaveHookContractLockEntryForMode(dataDir, entry, true); err != nil {
		t.Fatal(err)
	}
	claim, err := CaptureManagedHookContractCleanupClaimForOwner(
		dataDir,
		"codex",
		ownerSID,
		"DefenseClawGateway-ScopeA",
	)
	if err != nil {
		t.Fatal(err)
	}

	// Scope B deliberately keeps every ordinary connector-contract field
	// identical. Only its exact managed SCM identity changes, which must make
	// the old scope-A receipt a superseded CAS rather than deletion authority.
	entry.ManagedGatewayServiceName = "DefenseClawGateway-ScopeB"
	if err := SaveHookContractLockEntryForMode(dataDir, entry, true); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyManagedHookContractCleanupClaimForOwner(claim); !errors.Is(
		err,
		ErrWindowsManagedHookContractCleanupSuperseded,
	) {
		t.Fatalf("scope-A delayed purge error = %v, want typed supersession", err)
	}
	stored, err := loadManagedHookContractLockForOwner(dataDir, ownerSID)
	if err != nil {
		t.Fatal(err)
	}
	got, exists := stored.Connectors["codex"]
	if !exists || got.ManagedGatewayServiceName != "DefenseClawGateway-ScopeB" ||
		got.RawAgentVersion != "same-codex" || got.ContractID != "codex-hooks-v1" {
		t.Fatalf("scope-B connector entry changed: %+v", got)
	}
}

func TestCleanupCaptureDoesNotClaimCursorEntryFromNewGatewayScope(t *testing.T) {
	if err := requireWindowsCodexMachineAdministrator(); err != nil {
		t.Skipf("managed purge requires an elevated Administrator or LocalSystem token: %v", err)
	}
	dataDir := filepath.Join(t.TempDir(), ".defenseclaw")
	ownerSID := windowsProcessUserSIDForTest(t).String()
	if err := ReconcileManagedNativeHookRuntime(
		dataDir,
		"127.0.0.1:18970",
		"cursor",
		"scope-b-token",
	); err != nil {
		t.Fatal(err)
	}
	t.Setenv(WindowsGatewayServiceNameEnv, "DefenseClawGateway-ScopeB")
	entry, err := NewHookContractLockEntryForMode(
		SetupOpts{
			DataDir:           dataDir,
			ManagedEnterprise: true,
			AgentVersion:      "1.7.0",
			HookFailMode:      "closed",
		},
		NewCursorConnector(),
		"same-build",
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveHookContractLockEntryForMode(dataDir, entry, true); err != nil {
		t.Fatal(err)
	}

	claim, err := CaptureManagedHookContractCleanupClaimForOwner(
		dataDir,
		"cursor",
		ownerSID,
		"DefenseClawGateway-ScopeA",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !claim.Superseded || claim.EntryPresent || claim.EntrySHA256 != "" {
		t.Fatalf("scope-A capture claimed scope-B Cursor entry: %+v", claim)
	}
	result, err := ApplyManagedHookContractCleanupClaimForOwner(claim)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Superseded || result.Removed {
		t.Fatalf("scope-A cleanup result = %+v", result)
	}
	stored, err := loadManagedHookContractLockForOwner(dataDir, ownerSID)
	if err != nil {
		t.Fatal(err)
	}
	if got := stored.Connectors["cursor"].ManagedGatewayServiceName; got != "DefenseClawGateway-ScopeB" {
		t.Fatalf("scope-B Cursor contract changed to %q", got)
	}
}

func TestCleanupCaptureRejectsLegacyUnboundEntry(t *testing.T) {
	if err := requireWindowsCodexMachineAdministrator(); err != nil {
		t.Skipf("managed purge requires an elevated Administrator or LocalSystem token: %v", err)
	}
	dataDir := filepath.Join(t.TempDir(), ".defenseclaw")
	ownerSID := windowsProcessUserSIDForTest(t).String()
	if err := ReconcileManagedNativeHookRuntime(
		dataDir,
		"127.0.0.1:18970",
		"codex",
		"legacy-token",
	); err != nil {
		t.Fatal(err)
	}
	if err := SaveHookContractLockEntryForMode(dataDir, HookContractLockEntry{
		Connector:       "codex",
		RawAgentVersion: "legacy",
		ContractID:      "codex-hooks-v1",
		HookFailMode:    "closed",
	}, true); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureManagedHookContractCleanupClaimForOwner(
		dataDir,
		"codex",
		ownerSID,
		"DefenseClawGateway-ScopeA",
	); err == nil || !strings.Contains(err.Error(), "no valid gateway service binding") {
		t.Fatalf("legacy cleanup capture error = %v", err)
	}
}

func TestCleanupClaimMissingStateRequiresPersistedMutationBarrier(t *testing.T) {
	if err := requireWindowsCodexMachineAdministrator(); err != nil {
		t.Skipf("managed purge requires an elevated Administrator or LocalSystem token: %v", err)
	}
	for _, missing := range []string{"whole lock", "connector entry"} {
		for _, applicationStarted := range []bool{false, true} {
			name := "before barrier"
			if applicationStarted {
				name = "after barrier"
			}
			t.Run(missing+"/"+name, func(t *testing.T) {
				dataDir := filepath.Join(t.TempDir(), ".defenseclaw")
				ownerSID := windowsProcessUserSIDForTest(t).String()
				if err := ReconcileManagedNativeHookRuntime(
					dataDir,
					"127.0.0.1:18970",
					"codex",
					"scoped-token",
				); err != nil {
					t.Fatal(err)
				}
				entry := HookContractLockEntry{
					Connector:                 "codex",
					RawAgentVersion:           "same-codex",
					ContractID:                "codex-hooks-v1",
					HookFailMode:              "closed",
					ManagedGatewayServiceName: "DefenseClawGateway-ScopeA",
				}
				if err := SaveHookContractLockEntryForMode(dataDir, entry, true); err != nil {
					t.Fatal(err)
				}
				claim, err := CaptureManagedHookContractCleanupClaimForOwner(
					dataDir,
					"codex",
					ownerSID,
					"DefenseClawGateway-ScopeA",
				)
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(dataDir, hookContractLockFile)
				switch missing {
				case "whole lock":
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				case "connector entry":
					lock, err := loadManagedHookContractLockForOwner(dataDir, ownerSID)
					if err != nil {
						t.Fatal(err)
					}
					delete(lock.Connectors, "codex")
					lock.SharedHookScriptDigests = nil
					lock.UpdatedAt = nextHookContractTimestamp(time.Now(), lock.UpdatedAt)
					body, err := json.MarshalIndent(lock, "", "  ")
					if err != nil {
						t.Fatal(err)
					}
					target, err := windows.StringToSid(ownerSID)
					if err != nil {
						t.Fatal(err)
					}
					if err := writeManagedTargetRuntimeFileForTarget(
						path,
						append(body, '\n'),
						true,
						target,
					); err != nil {
						t.Fatal(err)
					}
				}

				claim.ApplicationStarted = applicationStarted
				result, err := ApplyManagedHookContractCleanupClaimForOwner(claim)
				if !applicationStarted {
					if err == nil || !strings.Contains(err.Error(), "before the cleanup mutation barrier") {
						t.Fatalf("pre-barrier missing state result=%+v error=%v", result, err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if !result.AlreadyAbsent || result.Removed || result.Superseded {
					t.Fatalf("post-barrier missing state result = %+v", result)
				}
			})
		}
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
			Connector:                 name,
			RawAgentVersion:           "old-" + name,
			ContractID:                name + "-hooks-v1",
			HookFailMode:              "closed",
			ManagedGatewayServiceName: "DefenseClawGateway-ScopeA",
		}, true); err != nil {
			t.Fatalf("save %s managed contract: %v", name, err)
		}
	}

	for index, name := range connectors {
		if err := ClearManagedHookContractLockEntryForOwner(
			dataDir,
			name,
			ownerSID,
			"DefenseClawGateway-ScopeA",
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
