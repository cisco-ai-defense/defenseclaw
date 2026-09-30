// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestRefusePerUserGatewayOnManagedHost(t *testing.T) {
	descriptor := filepath.Join(t.TempDir(), "managed-runtime.json")
	restore, restoreWindows, restoreTrust := managedHostDescriptorPath, managedHostWindowsStandalone, managedHostRecordTrusted
	managedHostDescriptorPath = func() string { return descriptor }
	managedHostWindowsStandalone = func() (string, bool) { return "", false }
	managedHostRecordTrusted = func(string) error { return nil }
	defer func() {
		managedHostDescriptorPath, managedHostWindowsStandalone, managedHostRecordTrusted = restore, restoreWindows, restoreTrust
	}()
	t.Setenv(managed.DeploymentModeEnv, "")

	if err := refusePerUserGatewayOnManagedHost(); err != nil {
		t.Fatalf("unmanaged host refused: %v", err)
	}
	if err := os.WriteFile(descriptor, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := refusePerUserGatewayOnManagedHost()
	if err == nil || !strings.Contains(err.Error(), "managed by your organization") {
		t.Fatalf("managed host allowed a per-user gateway: %v", err)
	}
	t.Setenv(managed.DeploymentModeEnv, managed.DeploymentModeManagedEnterprise)
	if err := refusePerUserGatewayOnManagedHost(); err != nil {
		t.Fatalf("managed service refused: %v", err)
	}
}

func TestRefusePerUserGatewayOnWindowsStandaloneHost(t *testing.T) {
	restore, restoreWindows := managedHostDescriptorPath, managedHostWindowsStandalone
	managedHostDescriptorPath = func() string { return "" }
	defer func() { managedHostDescriptorPath, managedHostWindowsStandalone = restore, restoreWindows }()
	t.Setenv(managed.DeploymentModeEnv, "")

	managedHostWindowsStandalone = func() (string, bool) { return "", false }
	if err := refusePerUserGatewayOnManagedHost(); err != nil {
		t.Fatalf("a host without a standalone deployment refused: %v", err)
	}
	managedHostWindowsStandalone = func() (string, bool) {
		return `C:\ProgramData\Cisco\DefenseClaw\install\deployment.json`, true
	}
	err := refusePerUserGatewayOnManagedHost()
	if err == nil || !strings.Contains(err.Error(), "enterprise windows status") {
		t.Fatalf("a Windows standalone host allowed a per-user gateway: %v", err)
	}
	t.Setenv(managed.DeploymentModeEnv, managed.DeploymentModeManagedEnterprise)
	if err := refusePerUserGatewayOnManagedHost(); err != nil {
		t.Fatalf("the managed gateway service refused: %v", err)
	}
}

// On a Windows standalone computer `defenseclaw setup rotate-token` was an
// unknown command; other hosts get no setup command.
func TestManagedWindowsSetupAnswer(t *testing.T) {
	restore := managedHostWindowsStandalone
	defer func() { managedHostWindowsStandalone = restore }()
	root := &cobra.Command{Use: "defenseclaw"}
	managedHostWindowsStandalone = func() (string, bool) { return "", false }
	addManagedWindowsSetupAnswer(root)
	if len(root.Commands()) != 0 {
		t.Fatalf("a host without a standalone deployment got %v", root.Commands())
	}
	managedHostWindowsStandalone = func() (string, bool) { return `HKLM\SOFTWARE\Cisco\DefenseClaw\Enterprise`, true }
	addManagedWindowsSetupAnswer(root)
	root.SetArgs([]string{"setup", "rotate-token", "--yes"})
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "managed by your organization") {
		t.Fatalf("setup rotate-token on a managed Windows computer: %v", err)
	}
}

func TestRefusePerUserGatewayIgnoresAnUntrustedDescriptor(t *testing.T) {
	descriptor := filepath.Join(t.TempDir(), "managed-runtime.json")
	if err := os.WriteFile(descriptor, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	restore, restoreWindows, restoreTrust := managedHostDescriptorPath, managedHostWindowsStandalone, managedHostRecordTrusted
	managedHostDescriptorPath = func() string { return descriptor }
	managedHostWindowsStandalone = func() (string, bool) { return "", false }
	var checked string
	managedHostRecordTrusted = func(path string) error {
		checked = path
		return errors.New("owner is a standard user")
	}
	defer func() {
		managedHostDescriptorPath, managedHostWindowsStandalone, managedHostRecordTrusted = restore, restoreWindows, restoreTrust
	}()
	t.Setenv(managed.DeploymentModeEnv, "")

	// A descriptor any user could have planted must not disable every other
	// user's per-user gateway.
	if err := refusePerUserGatewayOnManagedHost(); err != nil {
		t.Fatalf("an untrusted descriptor refused the per-user gateway: %v", err)
	}
	if checked != descriptor {
		t.Fatalf("trust check saw %q, want the descriptor %q", checked, descriptor)
	}
}

func TestManagedRecordTrustedNeedsAnAdministratorOnlyDirectory(t *testing.T) {
	root := filepath.Join(string(filepath.Separator), "pd")
	record := filepath.Join(root, "Cisco", "DefenseClaw", "install", "deployment.json")
	install := filepath.Dir(record)
	product := filepath.Dir(install)
	vendor := filepath.Dir(product)
	denied := &fs.PathError{Op: "inspect", Path: "x", Err: fs.ErrPermission}
	untrusted := errors.New("owner is a standard user")
	userWritable := errors.New("untrusted principal has write-like access")

	for _, test := range []struct {
		name    string
		file    error
		dirs    map[string]error // missing entry = denied
		trusted bool
	}{
		{name: "inspectable administrator record", file: nil, trusted: true},
		{name: "user-owned record", file: untrusted},
		{
			name: "standard user below an administrator-only product directory",
			file: denied, dirs: map[string]error{product: nil}, trusted: true,
		},
		{
			name: "standard user below an administrator-only vendor directory",
			file: denied, dirs: map[string]error{vendor: nil}, trusted: true,
		},
		{
			name: "locked record in a user-writable directory",
			file: denied, dirs: map[string]error{product: userWritable, vendor: nil},
		},
		{
			name: "locked record in a user-created directory",
			file: denied, dirs: map[string]error{install: untrusted, vendor: nil},
		},
		{name: "nothing inspectable below the data root", file: denied, dirs: map[string]error{root: nil}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var visited []string
			err := managedRecordTrusted(record, root,
				func(path string) error {
					if path != record {
						t.Fatalf("file validator got %q", path)
					}
					return test.file
				},
				func(dir string) error {
					visited = append(visited, dir)
					if dir == root || !strings.HasPrefix(dir, root) {
						t.Fatalf("directory validator reached %q, at or above the data root", dir)
					}
					if result, ok := test.dirs[dir]; ok {
						return result
					}
					return fmt.Errorf("inspect %s: %w", dir, denied)
				},
			)
			if (err == nil) != test.trusted {
				t.Fatalf("managedRecordTrusted = %v (visited %v), want trusted=%t", err, visited, test.trusted)
			}
		})
	}
}

// standaloneGuardFixture models a Windows standalone host for the guard's
// decision: the deployment record, its ancestors below %ProgramData% and the
// gateway service the Service Control Manager reports.
type standaloneGuardFixture struct {
	root, record, vendor, gatewayPath string
}

func newStandaloneGuardFixture() standaloneGuardFixture {
	root := filepath.Join(string(filepath.Separator), "pd")
	return standaloneGuardFixture{
		root:        root,
		record:      filepath.Join(root, "Cisco", "DefenseClaw", "install", "deployment.json"),
		vendor:      filepath.Join(root, "Cisco"),
		gatewayPath: `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-gateway.exe`,
	}
}

// standardUserTrust is the walk a standard user makes on a real standalone
// host: the record and the administrator-only product directories hide their
// security settings, and the vendor directory decides with vendorErr.
func (f standaloneGuardFixture) standardUserTrust(vendorErr error) func(string) error {
	denied := &fs.PathError{Op: "inspect", Path: f.record, Err: fs.ErrPermission}
	return func(path string) error {
		return managedRecordTrusted(path, f.root,
			func(string) error { return denied },
			func(dir string) error {
				if dir == f.vendor {
					return vendorErr
				}
				return fmt.Errorf("inspect %s: %w", dir, denied)
			})
	}
}

// service reports the gateway service registered with image, or registerErr.
func (f standaloneGuardFixture) service(image string, registerErr error) func() (string, error) {
	return func() (string, error) {
		if registerErr != nil {
			return "", registerErr
		}
		if err := standaloneGatewayServiceImageMatches(image, f.gatewayPath); err != nil {
			return "", err
		}
		return "service DefenseClawGateway runs " + f.gatewayPath, nil
	}
}

var (
	// userWritableVendorDirectory is what the strict check reports for a
	// vendor directory that keeps the ProgramData Users create-child grant,
	// as one created by Secure Client or another Cisco product does.
	userWritableVendorDirectory = errors.New(`C:\ProgramData\Cisco: untrusted Windows principal S-1-5-32-545 has write-like access mask 0x116`)
	gatewayServiceNotRegistered = errors.New("open service DefenseClawGateway: The specified service does not exist as an installed service.")
	standaloneGatewayImage      = `"C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-gateway.exe"`
	secureClientGatewayImage    = `"C:\Program Files\Cisco\Cisco Secure Client\DefenseClaw\bin\defenseclaw-gateway.exe"`
)

func TestManagedStandaloneRecordCountsFallsBackToTheGatewayService(t *testing.T) {
	f := newStandaloneGuardFixture()
	planted := func(string) error { return errors.New("owner is a standard user") }
	for _, test := range []struct {
		name    string
		trust   func(string) error
		service func() (string, error)
		counts  bool
		where   string
	}{
		{
			name:  "administrator reads the record",
			trust: func(string) error { return nil }, service: f.service("", gatewayServiceNotRegistered),
			counts: true, where: f.record,
		},
		{
			name:  "standard user below an administrator-only vendor directory",
			trust: f.standardUserTrust(nil), service: f.service("", gatewayServiceNotRegistered),
			counts: true, where: f.record,
		},
		{
			name:  "standard user below a user-writable vendor directory on a standalone host",
			trust: f.standardUserTrust(userWritableVendorDirectory), service: f.service(standaloneGatewayImage, nil),
			counts: true, where: "service DefenseClawGateway runs " + f.gatewayPath,
		},
		{
			name:  "standard user below a user-writable vendor directory without the gateway service",
			trust: f.standardUserTrust(userWritableVendorDirectory), service: f.service("", gatewayServiceNotRegistered),
		},
		{
			name:  "standard user below a user-writable vendor directory with the Secure Client gateway",
			trust: f.standardUserTrust(userWritableVendorDirectory), service: f.service(secureClientGatewayImage, nil),
		},
		{
			name:  "planted record without the gateway service",
			trust: planted, service: f.service("", gatewayServiceNotRegistered),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			where, err := managedStandaloneRecordCounts(f.record, test.trust, test.service)
			if (err == nil) != test.counts {
				t.Fatalf("managedStandaloneRecordCounts = %q, %v; want counts=%t", where, err, test.counts)
			}
			if where != test.where {
				t.Fatalf("where = %q, want %q", where, test.where)
			}
		})
	}
}

func TestStandaloneGatewayServiceImageMatches(t *testing.T) {
	gateway := `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-gateway.exe`
	for image, want := range map[string]bool{
		standaloneGatewayImage: true,
		`"c:\program files\cisco\defenseclaw\bin\DEFENSECLAW-GATEWAY.EXE"`:          true,
		`  "C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-gateway.exe" --flag`: true,
		`C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-gateway.exe`:            false,
		`"C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-gateway.exe`:           false,
		`"C:\Program Files\Cisco\DefenseClaw-Cert\lab\bin\defenseclaw-gateway.exe"`: false,
		`"C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-gateway.exe.bak"`:      false,
		secureClientGatewayImage: false,
		``:                       false,
	} {
		if got := standaloneGatewayServiceImageMatches(image, gateway) == nil; got != want {
			t.Errorf("standaloneGatewayServiceImageMatches(%q) matched=%t, want %t", image, got, want)
		}
	}
	if standaloneGatewayServiceImageMatches(standaloneGatewayImage, "") == nil {
		t.Error("an empty gateway path must never match")
	}
}
