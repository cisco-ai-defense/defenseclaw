// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

func TestSecureClientClassificationIgnoresProcessMachineRootEnvironment(t *testing.T) {
	want, err := winpath.TrustedEnterpriseRoots(winpath.EnterpriseProfileSecureClient)
	if err != nil {
		t.Skipf("machine roots unavailable: %v", err)
	}
	poison := `C:\Users\Sample\Controlled`
	t.Setenv("ProgramFiles", poison)
	t.Setenv("ProgramData", poison)
	got, err := winpath.TrustedEnterpriseRoots(winpath.EnterpriseProfileSecureClient)
	if err != nil || got != want {
		t.Fatalf("process environment selected Secure Client roots: got=%+v err=%v want=%+v", got, err, want)
	}
	if secureClientServiceMatches(got, poison+`\bin\defenseclaw-gateway.exe`) {
		t.Fatal("user-controlled service path selected Secure Client handling")
	}
	if !secureClientServiceMatches(got, `"`+got.InstallRoot+`\bin\defenseclaw-gateway.exe"`) {
		t.Fatal("registered Secure Client service path not recognized")
	}
}

func TestSecureClientLayoutClassificationWithProtectedMetadata(t *testing.T) {
	roots, err := winpath.TrustedEnterpriseRoots(winpath.EnterpriseProfileSecureClient)
	if err != nil {
		t.Skipf("machine roots unavailable: %v", err)
	}
	serviceImage := `"` + roots.InstallRoot + `\bin\defenseclaw-gateway.exe"`
	for _, tc := range []struct {
		name  string
		state winpath.EnterpriseDeploymentState
		image string
		want  bool
	}{
		{"installed", winpath.EnterpriseDeploymentInstalled, serviceImage, true},
		{"standard user cannot read metadata", winpath.EnterpriseDeploymentUnknown, serviceImage, true},
		{"no installation", winpath.EnterpriseDeploymentAbsent, serviceImage, false},
		{"removed installation", winpath.EnterpriseDeploymentTombstone, serviceImage, false},
		{"no service", winpath.EnterpriseDeploymentUnknown, "", false},
		{"spoofed service path", winpath.EnterpriseDeploymentUnknown, `C:\Users\Sample\Controlled\bin\defenseclaw-gateway.exe`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := secureClientLayoutMatches(roots, tc.state, tc.image); got != tc.want {
				t.Fatalf("Secure Client layout = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSecureClientHostRequiresProtectedLayoutAndRegisteredService(t *testing.T) {
	roots, err := winpath.EnterpriseRootsFor(winpath.EnterpriseProfileSecureClient, `C:\Program Files`, `C:\ProgramData`)
	if err != nil {
		t.Fatal(err)
	}
	serviceImage := `"` + roots.InstallRoot + `\bin\defenseclaw-gateway.exe"`
	for _, tc := range []struct {
		name   string
		state  winpath.EnterpriseDeploymentState
		failAt string
		image  string
		want   bool
	}{
		{"installed", winpath.EnterpriseDeploymentInstalled, "", serviceImage, true},
		{"protected metadata unreadable", winpath.EnterpriseDeploymentUnknown, "", serviceImage, true},
		{"metadata absent", winpath.EnterpriseDeploymentAbsent, "transaction", serviceImage, false},
		// A first install writes the deployment record when its transaction
		// commits; its protected transaction record stands in until then.
		{"first install in progress", winpath.EnterpriseDeploymentAbsent, "", serviceImage, true},
		{"first install in progress, install marker missing", winpath.EnterpriseDeploymentAbsent, "marker", serviceImage, false},
		{"first install in progress, no registered service", winpath.EnterpriseDeploymentAbsent, "", "", false},
		{"deployment removed", winpath.EnterpriseDeploymentTombstone, "", serviceImage, false},
		{"machine roots unavailable", winpath.EnterpriseDeploymentInstalled, "roots", serviceImage, false},
		{"metadata inspection fails", winpath.EnterpriseDeploymentInstalled, "deployment", serviceImage, false},
		{"install directory untrusted", winpath.EnterpriseDeploymentInstalled, "directory", serviceImage, false},
		{"SYSTEM install marker missing or untrusted", winpath.EnterpriseDeploymentInstalled, "marker", serviceImage, false},
		{"gateway file untrusted", winpath.EnterpriseDeploymentInstalled, "file", serviceImage, false},
		{"service lookup fails", winpath.EnterpriseDeploymentInstalled, "service", serviceImage, false},
		{"service image unquoted", winpath.EnterpriseDeploymentInstalled, "", roots.InstallRoot + `\bin\defenseclaw-gateway.exe`, false},
		{"service image elsewhere", winpath.EnterpriseDeploymentInstalled, "", `"C:\Users\Sample\Controlled\bin\defenseclaw-gateway.exe"`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			failure := errors.New("fixture lookup failed")
			checks := secureClientClassificationChecks{
				roots: func(profile string) (winpath.EnterpriseRoots, error) {
					if profile != winpath.EnterpriseProfileSecureClient {
						t.Fatalf("requested profile %q", profile)
					}
					if tc.failAt == "roots" {
						return winpath.EnterpriseRoots{}, failure
					}
					return roots, nil
				},
				deployment: func(profile, path string) (winpath.EnterpriseDeployment, error) {
					if profile != roots.Profile || path != roots.MetadataPath {
						t.Fatalf("inspected %q, %q", profile, path)
					}
					if tc.failAt == "deployment" {
						return winpath.EnterpriseDeployment{}, failure
					}
					return winpath.EnterpriseDeployment{State: tc.state}, nil
				},
				trustedDir: func(path, _ string) error {
					if path != roots.InstallRoot {
						t.Fatalf("validated directory %q", path)
					}
					if tc.failAt == "directory" {
						return failure
					}
					return nil
				},
				trustedMarker: func(path, _ string) error {
					if path != roots.InstallRoot+`\secure-client.install` {
						t.Fatalf("validated marker %q", path)
					}
					if tc.failAt == "marker" {
						return failure
					}
					return nil
				},
				trustedFile: func(path, _ string) error {
					if path != roots.InstallRoot+`\bin\defenseclaw-gateway.exe` {
						t.Fatalf("validated file %q", path)
					}
					if tc.failAt == "file" {
						return failure
					}
					return nil
				},
				trustedTransaction: func(path, _ string) error {
					if path != filepath.Join(filepath.Dir(roots.MetadataPath), "pending.json") {
						t.Fatalf("validated transaction record %q", path)
					}
					if tc.state != winpath.EnterpriseDeploymentAbsent {
						t.Fatalf("transaction record consulted for a %s deployment", tc.state)
					}
					if tc.failAt == "transaction" {
						return failure
					}
					return nil
				},
				serviceImage: func(name string) (string, error) {
					if name != managed.StandaloneWindowsGatewaySvc {
						t.Fatalf("queried service %q", name)
					}
					if tc.failAt == "service" {
						return "", failure
					}
					return tc.image, nil
				},
			}
			if got := classifySecureClientHost(checks); got != tc.want {
				t.Fatalf("Secure Client host = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestWindowsManagedRecordTrustUsesRealACLs checks the guard's validators on
// real NTFS security descriptors: an administrator-owned record in an
// administrator-only tree is trusted, and the same record owned by the Users
// group, as a planted file would be, is not. It needs an elevated shell (to
// set the owners).
//
// The fixture is built so that the native CI runs it rather than skipping
// (#1300): that job makes new objects owned by the runner user, which the
// trust check rightly refuses, and its TEMP sits under user-owned folders.
// So the root is created under %ProgramData%, whose stock ancestors the
// production checks already accept, and the fixture is given the
// BUILTIN\Administrators owner explicitly.
func TestWindowsManagedRecordTrustUsesRealACLs(t *testing.T) {
	programData, err := winpath.TrustedProgramData()
	if err != nil {
		t.Skipf("resolve ProgramData: %v", err)
	}
	root, err := os.MkdirTemp(programData, "dc-record-acl-test-")
	if err != nil {
		t.Skipf("create a fixture under ProgramData: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	icacls := func(args ...string) error {
		out, err := exec.Command("icacls", args...).CombinedOutput()
		if err != nil {
			t.Logf("icacls %v: %v: %s", args, err, out)
		}
		return err
	}
	// Administrator-only tree: SYSTEM and Administrators full control,
	// Users read, nothing inherited from the temp location.
	if err := icacls(root, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-32-545:(OI)(CI)RX"); err != nil {
		t.Skip("cannot set an administrator-only ACL here")
	}
	record := filepath.Join(root, "Cisco", "DefenseClaw", "install", "deployment.json")
	if err := os.MkdirAll(filepath.Dir(record), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(record, []byte(`{"state":"installed"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := icacls(root, "/setowner", "*S-1-5-32-544", "/T", "/C"); err != nil {
		t.Skip("setting the Administrators owner needs an elevated shell")
	}
	if err := managed.ValidateTrustedRuntimeDir(root, "test root"); err != nil {
		t.Fatalf("an Administrators-owned, administrator-only root under ProgramData is not trusted: %v", err)
	}
	validateFile := func(path string) error { return managed.ValidateTrustedFilePath(path, "managed deployment record") }
	validateDir := func(dir string) error { return managed.ValidateTrustedRuntimeDir(dir, "managed deployment directory") }
	stop := filepath.Dir(root)
	if err := managedRecordTrusted(record, stop, validateFile, validateDir); err != nil {
		t.Fatalf("an administrator-owned record was not trusted: %v", err)
	}
	if err := icacls(record, "/setowner", "*S-1-5-32-545"); err != nil {
		t.Skip("setting a non-administrator owner needs an elevated shell")
	}
	if err := managedRecordTrusted(record, stop, validateFile, validateDir); err == nil {
		t.Fatal("a record owned by the Users group was trusted")
	}
}

// TestWindowsStandaloneGatewayServiceLookup reads the real Service Control
// Manager with the caller's token, the way the guard does: a host without the
// gateway service must not confirm a deployment.
func TestWindowsStandaloneGatewayServiceLookup(t *testing.T) {
	if _, err := windowsServiceImagePath(managed.StandaloneWindowsGatewaySvc); !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		t.Skipf("this host has a DefenseClawGateway service (%v)", err)
	}
	if where, err := managedHostStandaloneService(); err == nil {
		t.Fatalf("an unregistered gateway service confirmed a standalone deployment: %s", where)
	}
}
