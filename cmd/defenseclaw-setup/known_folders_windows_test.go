// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestSetupKnownFoldersIgnoreConnectorEnvironmentOverrides(t *testing.T) {
	wantInstall, err := defaultInstallRoot()
	if err != nil {
		t.Fatal(err)
	}
	wantData, err := defaultDataRoot()
	if err != nil {
		t.Fatal(err)
	}
	wantMaintenance, err := defaultMaintenancePath()
	if err != nil {
		t.Fatal(err)
	}
	wantTransaction, err := defaultTransactionRoot()
	if err != nil {
		t.Fatal(err)
	}
	wantPayloadTemp, err := defaultPayloadTempRoot()
	if err != nil {
		t.Fatal(err)
	}

	foreignProfile := t.TempDir()
	for name, value := range map[string]string{
		"USERPROFILE":  foreignProfile,
		"HOME":         foreignProfile,
		"LOCALAPPDATA": filepath.Join(foreignProfile, "AppData", "Local"),
		"APPDATA":      filepath.Join(foreignProfile, "AppData", "Roaming"),
	} {
		t.Setenv(name, value)
	}
	assertSameSetupPath(t, "install root", defaultInstallRoot, wantInstall)
	assertSameSetupPath(t, "data root", defaultDataRoot, wantData)
	assertSameSetupPath(t, "maintenance path", defaultMaintenancePath, wantMaintenance)
	assertSameSetupPath(t, "transaction root", defaultTransactionRoot, wantTransaction)
	assertSameSetupPath(t, "payload temp root", defaultPayloadTempRoot, wantPayloadTemp)
}

func assertSameSetupPath(t *testing.T, label string, resolve func() (string, error), want string) {
	t.Helper()
	got, err := resolve()
	if err != nil {
		t.Fatalf("resolve %s: %v", label, err)
	}
	if !samePath(got, want) {
		t.Fatalf("token-bound %s changed with connector environment: got %q, want %q", label, got, want)
	}
}

func TestDefaultInstallRootUsesUserProgramFilesKnownFolder(t *testing.T) {
	wantRoot, err := windows.KnownFolderPath(windows.FOLDERID_UserProgramFiles, windows.KF_FLAG_DEFAULT)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(wantRoot, "DefenseClaw")

	got, err := defaultInstallRoot()
	if err != nil {
		t.Fatal(err)
	}
	if !samePath(got, want) {
		t.Fatalf("defaultInstallRoot() = %q, want UserProgramFiles path %q", got, want)
	}
}
