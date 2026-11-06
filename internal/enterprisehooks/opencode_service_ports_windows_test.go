//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"os"
	"path/filepath"
	"testing"
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
	stampWindowsTargetsManifestTestSDDL(t, path, windowsTargetsManifestAdminFileSDDL)
	if _, err := LoadWindowsOpenCodeServicePorts(path); err == nil {
		t.Fatal("administrators-readable record was accepted")
	}
	if err := WriteWindowsOpenCodeServicePorts(path, want); err == nil {
		t.Fatal("writer adopted an ACL-drifted record")
	}
}
