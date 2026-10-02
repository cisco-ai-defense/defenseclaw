// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// stubWindowsEnterpriseRecords drives inspectTrustedWindowsEnterpriseDeployment
// with fixed raw states, record paths, and a validator.
func stubWindowsEnterpriseRecords(
	t *testing.T,
	states map[string]winpath.EnterpriseDeploymentState,
	paths map[string]string,
	validate func(string) error,
	elevated bool,
) {
	t.Helper()
	originalRoots := windowsEnterpriseRecordRoots
	originalInspector := windowsEnterpriseRecordInspector
	originalValidator := windowsEnterpriseRecordValidator
	originalDeployment := windowsEnterpriseDeploymentInspector
	originalElevated := windowsEnterpriseIsElevated
	t.Cleanup(func() {
		windowsEnterpriseRecordRoots = originalRoots
		windowsEnterpriseRecordInspector = originalInspector
		windowsEnterpriseRecordValidator = originalValidator
		windowsEnterpriseDeploymentInspector = originalDeployment
		windowsEnterpriseIsElevated = originalElevated
	})
	windowsEnterpriseDeploymentInspector = inspectTrustedWindowsEnterpriseDeployment
	windowsEnterpriseIsElevated = func() bool { return elevated }
	windowsEnterpriseRecordRoots = func(profile string) (winpath.EnterpriseRoots, error) {
		roots, err := winpath.EnterpriseRootsFor(profile, `C:\Program Files`, `C:\ProgramData`)
		if path, ok := paths[profile]; ok {
			roots.MetadataPath = path
		}
		return roots, err
	}
	windowsEnterpriseRecordInspector = func(profile string) (winpath.EnterpriseDeployment, error) {
		roots, _ := windowsEnterpriseRecordRoots(profile)
		state, ok := states[profile]
		if !ok {
			state = winpath.EnterpriseDeploymentAbsent
		}
		return winpath.EnterpriseDeployment{Profile: profile, State: state, MetadataPath: roots.MetadataPath}, nil
	}
	windowsEnterpriseRecordValidator = validate
}

func TestInspectTrustedWindowsEnterpriseDeployment(t *testing.T) {
	untrusted := errors.New(`C:\ProgramData\Cisco\DefenseClaw: owner S-1-5-21-1-2-3-1001 is not trusted`)
	denied := fmt.Errorf(`C:\ProgramData\Cisco\DefenseClaw\install: %w`, os.ErrPermission)
	for _, tc := range []struct {
		name      string
		state     winpath.EnterpriseDeploymentState
		validate  error
		elevated  bool
		want      winpath.EnterpriseDeploymentState
		untrusted bool
	}{
		{name: "absent", state: winpath.EnterpriseDeploymentAbsent, validate: untrusted, elevated: true, want: winpath.EnterpriseDeploymentAbsent},
		{name: "administrator record", state: winpath.EnterpriseDeploymentInstalled, elevated: true, want: winpath.EnterpriseDeploymentInstalled},
		{name: "administrator tombstone", state: winpath.EnterpriseDeploymentTombstone, elevated: true, want: winpath.EnterpriseDeploymentTombstone},
		{name: "damaged administrator record", state: winpath.EnterpriseDeploymentUnknown, elevated: true, want: winpath.EnterpriseDeploymentUnknown},
		{name: "planted record", state: winpath.EnterpriseDeploymentInstalled, validate: untrusted, elevated: true, want: winpath.EnterpriseDeploymentAbsent, untrusted: true},
		{name: "planted unparseable record", state: winpath.EnterpriseDeploymentUnknown, validate: untrusted, elevated: true, want: winpath.EnterpriseDeploymentAbsent, untrusted: true},
		{name: "planted record seen by a standard user", state: winpath.EnterpriseDeploymentInstalled, validate: untrusted, want: winpath.EnterpriseDeploymentAbsent, untrusted: true},
		{name: "protected record seen by a standard user", state: winpath.EnterpriseDeploymentUnknown, validate: denied, want: winpath.EnterpriseDeploymentUnknown},
		{name: "unreadable record seen by an administrator", state: winpath.EnterpriseDeploymentUnknown, validate: denied, elevated: true, want: winpath.EnterpriseDeploymentAbsent, untrusted: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubWindowsEnterpriseRecords(t,
				map[string]winpath.EnterpriseDeploymentState{"standalone": tc.state}, nil,
				func(string) error { return tc.validate }, tc.elevated)
			deployment, err := inspectTrustedWindowsEnterpriseDeployment("standalone")
			if err != nil {
				t.Fatal(err)
			}
			if deployment.State != tc.want || (deployment.Untrusted != "") != tc.untrusted {
				t.Fatalf("deployment %+v, want state %q untrusted %t", deployment, tc.want, tc.untrusted)
			}
		})
	}
}

// A record planted under the default ProgramData ACL must not change the
// Secure Client lifecycle: the unprofiled Secure Client Setup still resolves
// to Secure Client and is not refused as a profile conflict, and a planted
// Secure Client record does not block a standalone install.
func TestPlantedDeploymentRecordDoesNotAffectLifecycleProfile(t *testing.T) {
	planted := filepath.Join(t.TempDir(), "deployment.json")
	if err := os.WriteFile(planted, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	validate := func(path string) error {
		if strings.EqualFold(path, planted) {
			// The real validator: the test's temporary directory is
			// writable by the current user, exactly like a planted tree.
			return windowsEnterpriseRecordValidatorDefault(path)
		}
		return nil
	}
	for _, tc := range []struct {
		name    string
		states  map[string]winpath.EnterpriseDeploymentState
		paths   map[string]string
		opts    windowsEnterpriseLifecycleOptions
		action  string
		want    string
		wantErr string
	}{
		{name: "secure client install next to a planted standalone record",
			states: map[string]winpath.EnterpriseDeploymentState{"standalone": winpath.EnterpriseDeploymentInstalled},
			paths:  map[string]string{"standalone": planted},
			opts:   windowsEnterpriseLifecycleOptions{brokerBinary: `C:\stage\defenseclaw-cmid-broker.exe`},
			action: "install", want: "secure_client"},
		{name: "secure client status next to a planted standalone record",
			states: map[string]winpath.EnterpriseDeploymentState{"standalone": winpath.EnterpriseDeploymentInstalled, "secure_client": winpath.EnterpriseDeploymentInstalled},
			paths:  map[string]string{"standalone": planted},
			action: "status", want: "secure_client"},
		{name: "standalone install next to a planted secure client record",
			states: map[string]winpath.EnterpriseDeploymentState{"secure_client": winpath.EnterpriseDeploymentInstalled},
			paths:  map[string]string{"secure_client": planted},
			opts:   windowsEnterpriseLifecycleOptions{profile: "standalone"},
			action: "install", want: "standalone"},
		{name: "a real standalone record still conflicts",
			states:  map[string]winpath.EnterpriseDeploymentState{"standalone": winpath.EnterpriseDeploymentInstalled, "secure_client": winpath.EnterpriseDeploymentInstalled},
			action:  "status",
			wantErr: "profile_conflict"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubWindowsEnterpriseRecords(t, tc.states, tc.paths, validate, true)
			opts := tc.opts
			err := resolveWindowsEnterpriseLifecycleProfile(tc.action, &opts)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if opts.resolvedProfile != tc.want {
				t.Fatalf("resolved %q, want %q", opts.resolvedProfile, tc.want)
			}
			if len(opts.ignoredDeploymentRecords) != 1 || !strings.Contains(opts.ignoredDeploymentRecords[0], planted) {
				t.Fatalf("ignored records %q", opts.ignoredDeploymentRecords)
			}
			if tc.want == "standalone" {
				result := newWindowsEnterpriseStandaloneResult(tc.action, &opts)
				if len(result.Warnings) != 1 || result.Warnings[0].Code != "untrusted_deployment_record" {
					t.Fatalf("standalone warnings %+v", result.Warnings)
				}
			}
		})
	}
}

// The per-user gateway guard honors only an administrator-owned marker key.
func TestWindowsEnterpriseMarkerRequiresAdministratorKey(t *testing.T) {
	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	path := `Software\DefenseClawMarkerTest-` + hex.EncodeToString(suffix)
	key, _, err := registry.CreateKey(registry.CURRENT_USER, path,
		registry.SET_VALUE|registry.QUERY_VALUE|windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.DeleteKey(registry.CURRENT_USER, path) })
	defer key.Close()
	if err := key.SetStringValue("Profile", "standalone"); err != nil {
		t.Fatal(err)
	}
	// A key the current user can write, as a planted marker would be.
	if windowsEnterpriseMarkerStandalone(key) {
		t.Fatal("a user-writable marker key was honored")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("setting an Administrators-owned key requires an elevated token")
	}
	descriptor, err := windows.SecurityDescriptorFromString("O:BAG:SYD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;BU)")
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetSecurityInfo(windows.Handle(key), windows.SE_REGISTRY_KEY,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	protected, err := registry.OpenKey(registry.CURRENT_USER, path, registry.QUERY_VALUE|windows.READ_CONTROL)
	if err != nil {
		t.Fatal(err)
	}
	defer protected.Close()
	if !windowsEnterpriseMarkerStandalone(protected) {
		t.Fatalf("an administrator-owned marker key was refused: %v", validateWindowsEnterpriseAdminRegistryKey(protected))
	}
}
