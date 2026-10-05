// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A failed install's rollback runs target-runtime cleanup after the hook
// enumerator has republished targets.yaml (it does so on every row change, for
// example a newly discovered agent, while the install waits for readiness).
// Cleanup refused any digest change, so the rollback failed, the transaction
// stayed pending and every recovery refused again. Cleanup now
// accepts a republished manifest that keeps exactly the planned roots.
func TestWindowsManagedRuntimeCleanupAcceptsRepublishedRowsOfThePlannedRoots(t *testing.T) {
	target := currentWindowsTestSID(t)
	home := newWindowsTargetOwnedTestHome(t, target)
	dataDir := filepath.Join(home, ".defenseclaw")
	hookDir := filepath.Join(dataDir, "hooks")
	if _, err := ensureWindowsTargetOwnedDirectoryTree(home, hookDir, target); err != nil {
		t.Fatal(err)
	}
	manifest := windowsManagedRuntimeTestManifest(home, target)
	digest := strings.Repeat("4", 64)
	plan, err := PlanWindowsManagedRuntimeRoots(manifest, `C:\ProgramData\DefenseClaw\etc\targets.yaml`, digest)
	if err != nil {
		t.Fatal(err)
	}
	request := WindowsManagedRuntimeRequest{SchemaVersion: WindowsManagedRuntimeRequestSchemaVersion, Plan: plan}

	// A republication that moves a planned root (same SID, another profile
	// root) is still refused and leaves the planned root alone.
	otherHome := newWindowsTargetOwnedTestHome(t, target)
	moved := Manifest{Version: manifest.Version}
	for _, row := range manifest.Targets {
		row.UserHome = otherHome
		row.DataDir = filepath.Join(otherHome, ".defenseclaw")
		moved.Targets = append(moved.Targets, row)
	}
	if _, err := CleanupWindowsManagedRuntimeRoots(request, moved, strings.Repeat("6", 64)); err == nil ||
		!strings.Contains(err.Error(), "does not keep the planned profile roots") {
		t.Fatalf("cleanup with a moved root: err = %v, want the planned-roots refusal", err)
	}
	if _, err := os.Lstat(dataDir); err != nil {
		t.Fatalf("refused cleanup touched the planned root: %v", err)
	}

	// The enumerator adds a row for the same user and republishes.
	republished := manifest
	republished.Targets = append(append([]ManifestTarget(nil), manifest.Targets...), ManifestTarget{
		UserHome: home, SID: target.String(), DataDir: dataDir, Connector: "opencode", AgentVersion: "1.18.32",
	})
	republishedDigest := strings.Repeat("5", 64)
	claims, err := CleanupWindowsManagedRuntimeRoots(request, republished, republishedDigest)
	if err != nil {
		t.Fatalf("cleanup after a same-roots republication: %v", err)
	}
	if len(claims) != 1 || claims[0].Identity != plan.Roots[0].BaselineIdentity || claims[0].Created {
		t.Fatalf("cleanup claims = %+v", claims)
	}
	assertWindowsTargetOwnedCanonicalDirectory(t, dataDir, target)

	// Stage and finalize still bind the planned digest exactly.
	if _, err := StageWindowsManagedRuntimeRoots(plan, republished, republishedDigest, func([]WindowsManagedRuntimeClaim) error { return nil }); err == nil ||
		!strings.Contains(err.Error(), "digest changed after planning") {
		t.Fatalf("stage with a republished manifest: err = %v, want the digest refusal", err)
	}
	if _, err := FinalizeWindowsManagedRuntimeRoots(request, republished, republishedDigest); err == nil ||
		!strings.Contains(err.Error(), "digest changed after planning") {
		t.Fatalf("finalize with a republished manifest: err = %v, want the digest refusal", err)
	}
}

// An account deleted with its profile while Setup ran left the rollback
// cleanup failing on the missing profile folder ("inspect user home ...
// cannot find the file"), so the transaction stayed pending with every
// service stopped and no Setup could recover it (GAP-1293). The vanished
// profile has nothing to clean and is reported as its absent baseline.
func TestWindowsManagedRuntimeCleanupTreatsAVanishedProfileAsClean(t *testing.T) {
	target := currentWindowsTestSID(t)
	home := newWindowsTargetOwnedTestHome(t, target)
	manifest := windowsManagedRuntimeTestManifest(home, target)
	digest := strings.Repeat("4", 64)
	plan, err := PlanWindowsManagedRuntimeRoots(manifest, `C:\ProgramData\DefenseClaw\etc\targets.yaml`, digest)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Roots) != 1 || plan.Roots[0].Baseline != windowsManagedRuntimeBaselineAbsent {
		t.Fatalf("plan roots = %+v, want one absent baseline", plan.Roots)
	}
	if err := os.RemoveAll(home); err != nil {
		t.Fatal(err)
	}
	request := WindowsManagedRuntimeRequest{SchemaVersion: WindowsManagedRuntimeRequestSchemaVersion, Plan: plan}
	claims, err := CleanupWindowsManagedRuntimeRoots(request, manifest, digest)
	if err != nil {
		t.Fatalf("cleanup with a vanished profile: %v", err)
	}
	if len(claims) != 1 || claims[0].State != windowsManagedRuntimeStateAbsent || claims[0].Created ||
		claims[0].Identity != "" || !strings.EqualFold(claims[0].SID, target.String()) {
		t.Fatalf("cleanup claims = %+v, want one absent claim", claims)
	}
}
