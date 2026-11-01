//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
)

func stubEnterpriseHookSelfHeal(t *testing.T) *[]string {
	t.Helper()
	originalInstall := enterpriseWindowsManagedInstallRepair
	originalPolicy := enterpriseWindowsManagedPolicyArtifactsRepair
	originalServices := enterpriseWindowsManagedServiceSecurityRepair
	originalCfg := cfg
	t.Cleanup(func() {
		enterpriseWindowsManagedInstallRepair = originalInstall
		enterpriseWindowsManagedPolicyArtifactsRepair = originalPolicy
		enterpriseWindowsManagedServiceSecurityRepair = originalServices
		cfg = originalCfg
	})
	var calls []string
	enterpriseWindowsManagedInstallRepair = func(managed.ManagedInstallLayout, managed.CanonicalOptions) []managed.CanonicalResult {
		calls = append(calls, "install")
		return nil
	}
	enterpriseWindowsManagedPolicyArtifactsRepair = func() { calls = append(calls, "policy") }
	enterpriseWindowsManagedServiceSecurityRepair = func(names []string) []managed.ServiceSecurityResult {
		calls = append(calls, "services")
		return nil
	}
	return &calls
}

func TestRepairEnterpriseHookManagedInstallPlatformRunsEveryStep(t *testing.T) {
	calls := stubEnterpriseHookSelfHeal(t)
	state := t.TempDir()
	cfg = &config.Config{
		DeploymentMode: managed.DeploymentModeManagedEnterprise,
		DataDir:        filepath.Join(state, "runtime"),
	}
	repairEnterpriseHookManagedInstallPlatform()
	// The test temp folder is outside the trusted roots, so no layout is
	// derived; the policy and service steps still run on their own.
	if got := len(*calls); got != 2 || (*calls)[0] != "policy" || (*calls)[1] != "services" {
		t.Fatalf("calls = %v, want policy then services", *calls)
	}
}

func TestRepairEnterpriseHookManagedInstallPlatformWaitsForPendingTransaction(t *testing.T) {
	calls := stubEnterpriseHookSelfHeal(t)
	state := t.TempDir()
	if err := os.MkdirAll(filepath.Join(state, "install"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "install", "pending.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg = &config.Config{
		DeploymentMode: managed.DeploymentModeManagedEnterprise,
		DataDir:        filepath.Join(state, "runtime"),
	}
	repairEnterpriseHookManagedInstallPlatform()
	if len(*calls) != 0 {
		t.Fatalf("calls during a pending transaction = %v", *calls)
	}
	cfg = &config.Config{DataDir: filepath.Join(t.TempDir(), "runtime")}
	repairEnterpriseHookManagedInstallPlatform()
	if len(*calls) != 0 {
		t.Fatalf("calls outside managed mode = %v", *calls)
	}
}

// A foreign owner is adopted only on DefenseClaw's own objects inside the
// platform installer's tree; anywhere else, and under strict mode, the
// refusal stays.
func TestEnterpriseHookOwnerTransferAllowedOnlyInsideInstallerTree(t *testing.T) {
	inside := `C:\ProgramData\Cisco\Cisco Secure Client\DefenseClaw\runtime`
	if !enterpriseHookOwnerTransferAllowed(inside) {
		t.Fatalf("owner transfer refused for %s", inside)
	}
	for _, outside := range []string{"", t.TempDir()} {
		if enterpriseHookOwnerTransferAllowed(outside) {
			t.Fatalf("owner transfer allowed for %q", outside)
		}
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	user, err := windows.StringToSid("S-1-5-21-1-2-3-1001")
	if err != nil {
		t.Fatal(err)
	}
	adopted, err := enterpriseWindowsAdoptUntrustedOwner(inside, user, "managed data_dir")
	if err != nil || adopted == nil || !adopted.Equals(administrators) {
		t.Fatalf("adopted owner = %v, %v; want Administrators", adopted, err)
	}
	if _, err := enterpriseWindowsAdoptUntrustedOwner(t.TempDir(), user, "managed data_dir"); err == nil ||
		!strings.Contains(err.Error(), "S-1-5-21-1-2-3-1001") {
		t.Fatalf("outside error = %v, want a refusal naming the owner", err)
	}

	t.Setenv(managed.TrustStrictAncestorsEnv, "1")
	if enterpriseHookOwnerTransferAllowed(inside) {
		t.Fatal("strict pin allowed owner transfer")
	}
	if _, err := enterpriseWindowsAdoptUntrustedOwner(inside, user, "managed data_dir"); err == nil {
		t.Fatal("strict pin adopted an untrusted owner")
	}
}

func TestRepairEnterpriseHookManagedRuntimeAllowsOwnerTransferForDataDir(t *testing.T) {
	original := enterpriseWindowsManagedDataPathsRepair
	t.Cleanup(func() { enterpriseWindowsManagedDataPathsRepair = original })
	var seen []managed.CanonicalOptions
	enterpriseWindowsManagedDataPathsRepair = func(
		paths managed.ManagedDataPaths,
		opts managed.CanonicalOptions,
	) []managed.CanonicalResult {
		seen = append(seen, opts)
		return []managed.CanonicalResult{{Path: paths.DataDir, Outcome: managed.CanonicalRepaired}}
	}
	inside := `C:\ProgramData\Cisco\Cisco Secure Client\DefenseClaw\runtime`
	if err := repairEnterpriseHookManagedRuntimePlatform(inside, `NT SERVICE\DefenseClawGateway`); err != nil {
		t.Fatalf("repair: %v", err)
	}
	outside := filepath.Join(t.TempDir(), "runtime")
	if err := repairEnterpriseHookManagedRuntimePlatform(outside, `NT SERVICE\DefenseClawGateway`); err != nil {
		t.Fatalf("repair: %v", err)
	}
	if len(seen) != 2 || !seen[0].AllowUntrustedOwnerTransfer || seen[1].AllowUntrustedOwnerTransfer {
		t.Fatalf("owner transfer options = %+v, want allowed inside the installer tree only", seen)
	}
}
