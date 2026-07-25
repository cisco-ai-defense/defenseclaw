// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookruntime"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

func TestSetupStableHookSnapshotAllowsFailClosedStateRepair(t *testing.T) {
	for _, test := range []struct {
		name  string
		drift func(*testing.T, hookruntime.Paths)
	}{
		{
			name: "malformed-state",
			drift: func(t *testing.T, paths hookruntime.Paths) {
				if err := safefile.WritePrivate(paths.State, []byte("{")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "state-dacl",
			drift: func(t *testing.T, paths hookruntime.Paths) {
				addSetupReadOnlyDACLDrift(t, paths.State)
				if err := safefile.ValidatePrivateFile(paths.State); err == nil {
					t.Fatal("fixture state DACL remained trusted")
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			paths, gatewayPath, dataRoot := writeSetupHookStateFixture(t)
			test.drift(t, paths)
			active, err := stableHookRuntimeActiveAt(paths, gatewayPath, dataRoot)
			if err != nil || active {
				t.Fatalf("fail-closed setup posture = active=%t, error=%v", active, err)
			}
		})
	}
}

func TestSetupStableHookSnapshotRejectsValidForeignActiveBinding(t *testing.T) {
	paths, gatewayPath, dataRoot := writeSetupHookStateFixture(t)
	active, err := stableHookRuntimeActiveAt(paths, gatewayPath, dataRoot)
	if err != nil || !active {
		t.Fatalf("matching setup posture = active=%t, error=%v", active, err)
	}
	if _, err := stableHookRuntimeActiveAt(
		paths,
		gatewayPath,
		filepath.Join(t.TempDir(), "foreign-data"),
	); err == nil || !strings.Contains(err.Error(), "different data root") {
		t.Fatalf("foreign data-root error = %v", err)
	}
	if _, err := stableHookRuntimeActiveAt(
		paths,
		filepath.Join(t.TempDir(), hookruntime.GatewayName),
		dataRoot,
	); err == nil || !strings.Contains(err.Error(), "different installed gateway") {
		t.Fatalf("foreign gateway error = %v", err)
	}
}

func writeSetupHookStateFixture(t *testing.T) (hookruntime.Paths, string, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "DefenseClaw", "HookRuntime")
	paths := hookruntime.Paths{
		Root:     root,
		Launcher: filepath.Join(root, hookruntime.LauncherName),
		State:    filepath.Join(root, hookruntime.StateName),
	}
	if err := safefile.ProtectDirectory(paths.Root); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.Launcher, []byte("MZ-setup-hook"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := safefile.ProtectFile(paths.Launcher); err != nil {
		t.Fatal(err)
	}
	gatewayPath := filepath.Join(t.TempDir(), hookruntime.GatewayName)
	if err := os.WriteFile(gatewayPath, []byte("MZ-setup-gateway"), 0o600); err != nil {
		t.Fatal(err)
	}
	dataRoot := filepath.Join(t.TempDir(), "data")
	launcherDigest, err := fileSHA256(paths.Launcher)
	if err != nil {
		t.Fatal(err)
	}
	gatewayDigest, err := fileSHA256(gatewayPath)
	if err != nil {
		t.Fatal(err)
	}
	state := hookruntime.State{
		SchemaVersion:  hookruntime.SchemaVersion,
		Status:         hookruntime.StatusActive,
		RuntimeRoot:    paths.Root,
		LauncherPath:   paths.Launcher,
		LauncherSHA256: launcherDigest,
		DataRoot:       dataRoot,
		GatewayPath:    gatewayPath,
		GatewaySHA256:  gatewayDigest,
		TransactionID:  testCurrentTransactionID,
	}
	body, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := safefile.WritePrivate(paths.State, body); err != nil {
		t.Fatal(err)
	}
	return paths, gatewayPath, dataRoot
}

func addSetupReadOnlyDACLDrift(t *testing.T, path string) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatal(err)
	}
	entries := make([]windows.EXPLICIT_ACCESS, 0, 3)
	for _, entry := range []struct {
		sid  *windows.SID
		mask windows.ACCESS_MASK
	}{
		{sid: user.User.Sid, mask: windows.GENERIC_ALL},
		{sid: system, mask: windows.GENERIC_ALL},
		{sid: users, mask: windows.GENERIC_READ},
	} {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: entry.mask,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(entry.sid),
			},
		})
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		t.Fatal(err)
	}
	extended, err := winpath.Extended(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		extended,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	); err != nil {
		t.Fatal(err)
	}
}
