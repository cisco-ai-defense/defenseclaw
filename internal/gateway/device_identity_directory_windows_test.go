// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
	"golang.org/x/sys/windows"
)

// stubGatewayServiceProcess makes currentProcessIsGatewayService report
// isGateway for the rest of the test.
func stubGatewayServiceProcess(t *testing.T, isGateway bool) {
	t.Helper()
	previous := currentProcessIsGatewayService
	currentProcessIsGatewayService = func() bool { return isGateway }
	t.Cleanup(func() { currentProcessIsGatewayService = previous })
}

// untrustedIdentityTempDir is a temp dir a standard user can write. The
// caller's ownership alone is not enough: an elevated test run may be the
// built-in Administrator, which the managed trust walk accepts as drift.
func untrustedIdentityTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;BU)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestFreshIdentityManagedServiceDirectorySelection(t *testing.T) {
	dir := untrustedIdentityTempDir(t)
	t.Setenv(managed.DeploymentModeEnv, managed.DeploymentModeManagedEnterprise)
	t.Setenv(managed.WindowsServiceAccountEnv, `NT SERVICE\DefenseClawGateway`)

	t.Setenv(managed.EnterpriseProfileEnv, "")
	stubGatewayServiceProcess(t, false)
	if handled, err := validateFreshIdentityManagedServiceDirectory(dir); handled || err != nil {
		t.Fatalf("Secure Client non-service process = (%v, %v), want the private-directory check unchanged", handled, err)
	}

	// The Secure Client gateway service gets the managed service trust model
	// for its Administrators-owned runtime tree; a temp dir a standard user
	// can write is still refused by it.
	stubGatewayServiceProcess(t, true)
	handled, err := validateFreshIdentityManagedServiceDirectory(dir)
	if !handled || err == nil {
		t.Fatalf("Secure Client gateway service on an untrusted temp dir = (%v, %v), want handled and refused", handled, err)
	}
	stubGatewayServiceProcess(t, false)

	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
	handled, err = validateFreshIdentityManagedServiceDirectory(dir)
	if !handled || err == nil {
		t.Fatalf("standalone service on an untrusted temp dir = (%v, %v), want handled and refused", handled, err)
	}

	t.Setenv(managed.WindowsServiceAccountEnv, "")
	if handled, err := validateFreshIdentityManagedServiceDirectory(dir); handled || err != nil {
		t.Fatalf("standalone pin without a service account = (%v, %v), want not handled", handled, err)
	}
	t.Setenv(managed.EnterpriseProfileEnv, "")
	stubGatewayServiceProcess(t, true)
	if handled, err := validateFreshIdentityManagedServiceDirectory(dir); handled || err != nil {
		t.Fatalf("Secure Client gateway without a service account = (%v, %v), want not handled", handled, err)
	}
}

func TestFreshIdentityManagedServiceFileSelection(t *testing.T) {
	path := untrustedIdentityTempDir(t) + `\device.key`
	t.Setenv(managed.DeploymentModeEnv, managed.DeploymentModeManagedEnterprise)
	t.Setenv(managed.WindowsServiceAccountEnv, `NT SERVICE\DefenseClawGateway`)
	t.Setenv(managed.EnterpriseProfileEnv, "")
	stubGatewayServiceProcess(t, false)
	if handled, err := writeFreshIdentityManagedServiceFile(path, []byte("x")); handled || err != nil {
		t.Fatalf("Secure Client non-service process = (%v, %v), want the private writer unchanged", handled, err)
	}
	stubGatewayServiceProcess(t, true)
	if handled, err := writeFreshIdentityManagedServiceFile(path, []byte("x")); !handled || err == nil {
		t.Fatalf("Secure Client gateway service in an untrusted temp dir = (%v, %v), want handled and refused before writing", handled, err)
	}
	stubGatewayServiceProcess(t, false)
	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
	if handled, err := writeFreshIdentityManagedServiceFile(path, []byte("x")); !handled || err == nil {
		t.Fatalf("standalone service in an untrusted temp dir = (%v, %v), want handled and refused before writing", handled, err)
	}
}

// GAP-0911: quickstart created device.key with an extra full-control entry
// for BUILTIN\Administrators. Loading such a key gives it the DACL of a new
// one, this account and LocalSystem only, and keeps the identity.
func TestLoadIdentityNarrowsAdministratorsEntryOnExistingKey(t *testing.T) {
	t.Setenv(managed.DeploymentModeEnv, "")
	if !deviceIdentityOwnerIsAccount() {
		t.Skip("needs a local or domain account token")
	}
	keyFile := filepath.Join(testenv.PrivateTempDir(t), "device.key")
	first, err := LoadOrCreateIdentity(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	descriptor, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;;FA;;;" + sid + ")(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(keyFile, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	if safefile.ValidatePrivateFile(keyFile) == nil {
		t.Fatal("precondition: the Administrators entry did not make the key non-private")
	}
	second, err := LoadOrCreateIdentity(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if second.DeviceID != first.DeviceID {
		t.Fatalf("identity changed: %s -> %s", first.DeviceID, second.DeviceID)
	}
	if err := safefile.ValidatePrivateFile(keyFile); err != nil {
		t.Fatalf("existing key was not narrowed: %v", err)
	}
}
