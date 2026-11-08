// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// managedRuntimeDirWithACE makes a runtime directory the way the installer
// does (SYSTEM and Administrators full control, Administrators owner, the
// extra entries given) so the strict managed load meets a real ACL.
func managedRuntimeDirWithACE(t *testing.T, extra ...string) string {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an administrator token: the fixture needs a BUILTIN\\Administrators owner on its folders")
	}
	programData, err := winpath.TrustedProgramData()
	if err != nil {
		t.Skipf("resolve ProgramData: %v", err)
	}
	root, err := os.MkdirTemp(programData, "dc-config-runtime-acl-")
	if err != nil {
		t.Skipf("create a fixture under ProgramData: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	runtimeDir := filepath.Join(root, "runtime")
	if err := os.Mkdir(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	args := append([]string{root, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"}, extra...)
	if output, err := exec.Command("icacls.exe", args...).CombinedOutput(); err != nil {
		t.Skipf("set the fixture ACL: %v: %s", err, output)
	}
	output, err := exec.Command("icacls.exe", root, "/setowner", "*S-1-5-32-544", "/T", "/C").CombinedOutput()
	administrators, sidErr := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if sidErr != nil {
		t.Fatal(sidErr)
	}
	for _, path := range []string{root, runtimeDir} {
		sd, ownerErr := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
		if ownerErr != nil {
			t.Fatal(ownerErr)
		}
		if owner, _, ownerErr := sd.Owner(); ownerErr != nil || !owner.Equals(administrators) {
			t.Fatalf("icacls did not give %s the Administrators owner (owner %v, %v; icacls %v: %s)", path, owner, ownerErr, err, output)
		}
	}
	return runtimeDir
}

// The strict managed load (enterprise hooks verify and status run it in an
// unpinned administrator console) must accept the Modify entry the installer
// leaves for the install root own gateway service on the data_dir, and keep
// refusing every other writer.
func TestManagedLoadAcceptsTheScopeGatewayServiceWriterWithoutThePin(t *testing.T) {
	const production = `NT SERVICE\DefenseClawGateway`
	const certification = `NT SERVICE\DefenseClawCertGateway_0a1b2c3d4e`
	serviceModify := "*" + managed.WindowsServiceSIDString("DefenseClawGateway") + ":(OI)(CI)M"
	t.Setenv(managed.WindowsServiceAccountEnv, "")
	load := func(t *testing.T, dir, account string) error {
		t.Helper()
		previous := managedRuntimeGatewayAccount
		t.Cleanup(func() { managedRuntimeGatewayAccount = previous })
		managedRuntimeGatewayAccount = func() string { return account }
		return validateManagedEnterpriseRuntime(&Config{DataDir: dir}, false, true, false)
	}

	t.Run("the scope gateway service Modify entry is accepted", func(t *testing.T) {
		dir := managedRuntimeDirWithACE(t, serviceModify)
		if err := load(t, dir, production); err != nil {
			t.Fatalf("the installer gateway Modify entry was refused: %v", err)
		}
	})
	t.Run("an administrator-only account still refuses it", func(t *testing.T) {
		dir := managedRuntimeDirWithACE(t, serviceModify)
		if err := load(t, dir, ""); err == nil {
			t.Fatal("a console with no gateway writer accepted a service Modify entry")
		}
	})
	t.Run("the other scope gateway service is refused", func(t *testing.T) {
		dir := managedRuntimeDirWithACE(t, serviceModify)
		if err := load(t, dir, certification); err == nil {
			t.Fatal("the production gateway Modify entry was accepted in a certification scope")
		}
	})
	t.Run("a user write entry next to the service entry is refused", func(t *testing.T) {
		dir := managedRuntimeDirWithACE(t, serviceModify, "*S-1-5-32-545:(OI)(CI)M")
		if err := load(t, dir, production); err == nil {
			t.Fatal("a standard-user write entry was accepted next to the gateway entry")
		}
	})
}
