//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
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
