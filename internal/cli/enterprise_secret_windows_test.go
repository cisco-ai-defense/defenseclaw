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
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

func windowsSecretTestHarness(t *testing.T) string {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("the secret store is administrator-only; run elevated")
	}
	// An administrator-only directory at the root of the system drive stands
	// in for the deployment tree the gateway's credential reader trusts.
	root, err := os.MkdirTemp(os.Getenv("SystemDrive")+`\`, "dc-secret-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := applyWindowsSDDL(root, "O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "secrets")
	previousLayout, previousAccount := windowsSecretLayout, windowsSecretGatewayAccount
	previousInstalled, previousElevated, previousRestart := windowsSecretDeploymentInstalled, windowsSecretIsElevated, windowsSecretRestartGateway
	t.Cleanup(func() {
		windowsSecretLayout, windowsSecretGatewayAccount = previousLayout, previousAccount
		windowsSecretDeploymentInstalled, windowsSecretIsElevated, windowsSecretRestartGateway = previousInstalled, previousElevated, previousRestart
	})
	windowsSecretLayout = func() (managed.StandaloneLayout, error) {
		return managed.StandaloneLayout{GOOS: "windows", SecretsDir: dir}, nil
	}
	// A virtual service account that always exists stands in for the
	// gateway service.
	windowsSecretGatewayAccount = `NT SERVICE\TrustedInstaller`
	windowsSecretDeploymentInstalled = func() (bool, error) { return true, nil }
	windowsSecretRestartGateway = func() (bool, error) { return true, nil }
	return dir
}

func runWindowsSecretCommand(t *testing.T, action string, opts enterpriseSecretOptions, stdin string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	cmd.SetIn(strings.NewReader(stdin))
	err := runEnterpriseSecret(cmd, action, &opts)
	return out.String(), err
}

func TestWindowsSecretStoreUsesTheGatewayReaderDACL(t *testing.T) {
	dir := windowsSecretTestHarness(t)
	const value = "aid-test-key-0123456789"
	out, err := runWindowsSecretCommand(t, "set", enterpriseSecretOptions{name: "ai-defense-api-key", fromStdin: true, json: true}, value+"\r\n")
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	if strings.Contains(out, value) {
		t.Fatal("the credential value was printed")
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(out), &result); err != nil || result["ok"] != true || result["gateway_restarted"] != true {
		t.Fatalf("set result %s (%v)", out, err)
	}

	path := filepath.Join(dir, "ai-defense-api-key")
	extended, _ := winpath.Extended(path)
	sd, err := windows.GetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, _ := sd.Control()
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("the credential DACL inherits from its parent")
	}
	dacl, _, _ := sd.DACL()
	gateway, _ := managed.WindowsServiceAccountSID(windowsSecretGatewayAccount)
	system, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	admins, _ := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	seen := map[string]windows.ACCESS_MASK{}
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			t.Fatal(err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		seen[sid.String()] = ace.Mask
	}
	if len(seen) != 3 || seen[system.String()] == 0 || seen[admins.String()] == 0 || seen[gateway.String()] == 0 {
		t.Fatalf("credential DACL principals %v", seen)
	}
	if seen[gateway.String()]&(windows.FILE_WRITE_DATA|windows.DELETE|windows.WRITE_DAC) != 0 {
		t.Fatalf("the gateway SID may modify the credential: %#x", seen[gateway.String()])
	}

	// The directory grants the gateway SID exactly what its trust walk
	// needs on the directory itself: READ_CONTROL, SYNCHRONIZE,
	// FILE_READ_ATTRIBUTES and FILE_TRAVERSE, not inherited by files.
	dirACEs := windowsSecretTestACEs(t, dir)
	if len(dirACEs) != 3 {
		t.Fatalf("secrets directory DACL principals %v", dirACEs)
	}
	for _, sid := range []*windows.SID{system, admins} {
		ace, ok := dirACEs[sid.String()]
		if !ok || ace.flags&(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE) != windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE {
			t.Fatalf("secrets directory ACE for %s = %+v, want an inherited full-control ACE", sid, ace)
		}
	}
	reader, ok := dirACEs[gateway.String()]
	if !ok {
		t.Fatalf("secrets directory DACL has no ACE for the gateway SID %s: the gateway cannot read the directory's security descriptor", gateway)
	}
	const wantReaderAccess = windows.READ_CONTROL | windows.SYNCHRONIZE | windows.FILE_READ_ATTRIBUTES | windows.FILE_TRAVERSE
	if reader.mask != wantReaderAccess || reader.flags&(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE|windows.INHERIT_ONLY_ACE) != 0 {
		t.Fatalf("gateway directory ACE = mask %#x flags %#x, want mask %#x and no inheritance", uint32(reader.mask), reader.flags, uint32(wantReaderAccess))
	}

	t.Setenv(managed.WindowsServiceAccountEnv, windowsSecretGatewayAccount)
	got, source, err := managed.ResolveServiceCredential("ai-defense-api-key", dir)
	if err != nil || string(got) != value || source != managed.CredentialFromFile {
		t.Fatalf("the gateway reader rejected the stored credential: %q %s %v", got, source, err)
	}

	status, err := runWindowsSecretCommand(t, "status", enterpriseSecretOptions{json: true}, "")
	if err != nil || !strings.Contains(status, `"ai-defense-api-key"`) || strings.Contains(status, value) {
		t.Fatalf("status %s %v", status, err)
	}
	if _, err := runWindowsSecretCommand(t, "remove", enterpriseSecretOptions{name: "ai-defense-api-key"}, ""); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("credential still present: %v", err)
	}
}

func TestWindowsSecretRefusals(t *testing.T) {
	windowsSecretTestHarness(t)
	if _, err := runWindowsSecretCommand(t, "set", enterpriseSecretOptions{name: "../escape", fromStdin: true}, "x"); err == nil || commandExitCode(err) != windowsSecretExitInvalid {
		t.Fatalf("an unsafe name must be refused with 1639, got %v", err)
	}
	if _, err := runWindowsSecretCommand(t, "set", enterpriseSecretOptions{name: "ok-name", fromStdin: true}, "two\nlines"); err == nil {
		t.Fatal("a multi-line credential must be refused")
	}
	windowsSecretDeploymentInstalled = func() (bool, error) { return false, nil }
	if _, err := runWindowsSecretCommand(t, "set", enterpriseSecretOptions{name: "ok-name", fromStdin: true}, "x"); err == nil {
		t.Fatal("set without a standalone deployment must be refused")
	}
	windowsSecretIsElevated = func() bool { return false }
	if _, err := runWindowsSecretCommand(t, "status", enterpriseSecretOptions{}, ""); err == nil || commandExitCode(err) != windowsSecretExitFailure {
		t.Fatalf("a non-elevated token must be refused, got %v", err)
	}
}

type windowsSecretTestACE struct {
	mask  windows.ACCESS_MASK
	flags uint8
}

// windowsSecretTestACEs returns the allow ACEs of path's DACL by SID.
func windowsSecretTestACEs(t *testing.T, path string) map[string]windowsSecretTestACE {
	t.Helper()
	extended, err := winpath.Extended(path)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("%s has no DACL: %v", path, err)
	}
	aces := map[string]windowsSecretTestACE{}
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			t.Fatal(err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			t.Fatalf("%s: unexpected ACE type %#x", path, ace.Header.AceType)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		aces[sid.String()] = windowsSecretTestACE{mask: ace.Mask, flags: ace.Header.AceFlags}
	}
	return aces
}
