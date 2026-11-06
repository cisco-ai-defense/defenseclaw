//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestManagedWindowsOpenCodePortRecordIsSystemOnly(t *testing.T) {
	if err := requireWindowsEnterpriseLocalSystem(); err != nil {
		t.Skip("the SYSTEM-only record requires a LocalSystem test token")
	}
	dir := prepareWindowsTargetsManifestTestDirectory(t)
	path := WindowsOpenCodeServicePortsPath(filepath.Join(dir, "targets.yaml"))
	if ports, err := LoadWindowsOpenCodeServicePorts(path); err != nil || len(ports) != 0 {
		t.Fatalf("missing record = %v, %v", ports, err)
	}
	want := map[string]int{testLocalUserSID: 25001, testEntraUserSID: 25002}
	if err := WriteWindowsOpenCodeServicePorts(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := LoadWindowsOpenCodeServicePorts(path)
	if err != nil || len(got) != len(want) || got[testLocalUserSID] != 25001 || got[testEntraUserSID] != 25002 {
		t.Fatalf("record = %v, %v", got, err)
	}
	if err := validateWindowsOpenCodeServicePortsFile(path); err != nil {
		t.Fatalf("record ACL: %v", err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteWindowsOpenCodeServicePorts(path, want); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("unchanged record was rewritten")
	}
	if err := WriteWindowsOpenCodeServicePorts(path, map[string]int{testLocalUserSID: 25001, testEntraUserSID: 25001}); err == nil {
		t.Fatal("record writer accepted one port for two accounts")
	}
	stampWindowsTargetsManifestTestSDDL(t, path, windowsTargetsManifestAdminFileSDDL)
	if _, err := LoadWindowsOpenCodeServicePorts(path); err == nil {
		t.Fatal("administrators-readable record was accepted")
	}
	if err := WriteWindowsOpenCodeServicePorts(path, want); err == nil {
		t.Fatal("writer adopted an ACL-drifted record")
	}
}

func TestManagedWindowsOpenCodeContestedMarkIsSystemOnly(t *testing.T) {
	if err := requireWindowsEnterpriseLocalSystem(); err != nil {
		t.Skip("the SYSTEM-only record requires a LocalSystem test token")
	}
	dir := prepareWindowsTargetsManifestTestDirectory(t)
	path := WindowsOpenCodeServicePortsPath(filepath.Join(dir, "targets.yaml"))
	state := WindowsOpenCodeServicePortsState{
		Ports:     map[string]int{testLocalUserSID: 25001},
		Contested: []WindowsOpenCodeContestedPort{{Port: 25002, SIDs: []string{testLocalUserSID, testEntraUserSID}}},
	}
	if err := WriteWindowsOpenCodeServicePortsFull(path, state); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadWindowsOpenCodeServicePortsFull(path)
	if err != nil || !loaded.Exists || len(loaded.Contested) != 1 || loaded.Contested[0].Port != 25002 {
		t.Fatalf("contested mark was not kept: %+v, %v", loaded, err)
	}
	if err := WriteWindowsOpenCodeServicePortsFull(path, WindowsOpenCodeServicePortsState{Ports: state.Ports, Contested: []WindowsOpenCodeContestedPort{{Port: 25001, SIDs: state.Contested[0].SIDs}}}); err == nil {
		t.Fatal("writer accepted a contested mark on a bound port")
	}
	claimants, err := ClearWindowsOpenCodeContestedPort(path, 25002, "administrator", time.Now())
	if err != nil || len(claimants) != 2 {
		t.Fatalf("clear: %v, %v", claimants, err)
	}
	loaded, err = LoadWindowsOpenCodeServicePortsFull(path)
	if err != nil || len(loaded.Contested) != 0 || len(loaded.Cleared) != 1 || loaded.Ports[testLocalUserSID] != 25001 {
		t.Fatalf("clear changed a binding or lost its audit: %+v, %v", loaded, err)
	}
	if _, err := ClearWindowsOpenCodeContestedPort(path, 25002, "administrator", time.Now()); err == nil {
		t.Fatal("unmarked port was cleared twice")
	}
}

func TestManagedWindowsOpenCodeContestedMarkCanBeClearedByElevatedAdministrator(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() || !errors.Is(windowsEnterpriseMutationIdentityCheck(), errWindowsEnterpriseNotLocalSystem) {
		t.Skip("requires an elevated administrator token")
	}
	dir := prepareWindowsTargetsManifestTestDirectory(t)
	path := WindowsOpenCodeServicePortsPath(filepath.Join(dir, "targets.yaml"))
	state := WindowsOpenCodeServicePortsState{
		Ports:     map[string]int{testLocalUserSID: 25001},
		Contested: []WindowsOpenCodeContestedPort{{Port: 25002, SIDs: []string{testEntraUserSID}}},
	}
	if err := RunWithWindowsOwnerRestorePrivilege(func() error {
		return WriteWindowsOpenCodeServicePortsFull(path, state)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.ReadFile(path); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("administrator read of SYSTEM-only record = %v", err)
	}
	claimants, err := ClearWindowsOpenCodeContestedPort(path, 25002, "administrator", time.Now())
	if err != nil || len(claimants) != 1 || claimants[0] != testEntraUserSID {
		t.Fatalf("clear = %v, %v", claimants, err)
	}
	if err := RunWithWindowsOwnerRestorePrivilege(func() error {
		got, loadErr := LoadWindowsOpenCodeServicePortsFull(path)
		if loadErr != nil {
			return loadErr
		}
		if len(got.Contested) != 0 || len(got.Cleared) != 1 || got.Ports[testLocalUserSID] != 25001 {
			t.Errorf("clear changed a binding or lost its audit: %+v", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := RunWithWindowsOwnerRestorePrivilege(func() error {
		return validateWindowsOpenCodeServicePortsFile(path)
	}); err != nil {
		t.Fatalf("clear changed the SYSTEM-only ACL: %v", err)
	}
}
