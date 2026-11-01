// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-1202: the standalone install plan refuses the data folder of a
// per-user install (GAP-1434), but one a per-user install made after the
// plan has the same private DACL and inode, so stage and finalize took it
// over. Both refuse it the same way now.
func TestWindowsManagedRuntimeRefusesAPerUserInstallMadeAfterThePlan(t *testing.T) {
	previous := windowsEnterpriseStandaloneProcess
	t.Cleanup(func() { windowsEnterpriseStandaloneProcess = previous })
	windowsEnterpriseStandaloneProcess = func() bool { return true }
	target := currentWindowsTestSID(t)
	home := newWindowsTargetOwnedTestHome(t, target)
	dataDir := filepath.Join(home, ".defenseclaw")
	if _, err := ensureWindowsTargetOwnedDirectoryTree(home, filepath.Join(dataDir, "hooks"), target); err != nil {
		t.Fatal(err)
	}
	manifest := windowsManagedRuntimeTestManifest(home, target)
	digest := strings.Repeat("7", 64)
	plan, err := PlanWindowsManagedRuntimeRoots(manifest, `C:\ProgramData\DefenseClaw\etc\targets.yaml`, digest)
	if err != nil || len(plan.Roots) != 1 || plan.Roots[0].Baseline != windowsManagedRuntimeBaselineCanonical {
		t.Fatalf("install plan of a canonical managed folder: %+v, %v", plan.Roots, err)
	}
	claims, err := StageWindowsManagedRuntimeRoots(plan, manifest, digest, func([]WindowsManagedRuntimeClaim) error { return nil })
	if err != nil {
		t.Fatalf("stage of a canonical managed folder: %v", err)
	}
	// A per-user install writes its config after stage, before finalize.
	if err := os.WriteFile(filepath.Join(dataDir, "config.yaml"), []byte("gateway: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	want := dataDir + " holds config.yaml"
	request := WindowsManagedRuntimeRequest{SchemaVersion: WindowsManagedRuntimeRequestSchemaVersion, Plan: plan, Claims: claims}
	if _, err := FinalizeWindowsManagedRuntimeRoots(request, manifest, digest); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("finalize = %v, want the per-user install folder refused", err)
	}
	if _, err := StageWindowsManagedRuntimeRoots(plan, manifest, digest, func([]WindowsManagedRuntimeClaim) error { return nil }); err == nil ||
		!strings.Contains(err.Error(), want) {
		t.Fatalf("stage = %v, want the per-user install folder refused", err)
	}
}
