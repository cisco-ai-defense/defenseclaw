// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

func TestManagedModeAdvisoryIsInstalledInSafefile(t *testing.T) {
	if safefile.ManagedModeAdvisory == nil {
		t.Fatal("safefile.ManagedModeAdvisory is nil; the managed package must install it")
	}
}

func TestManagedModeAdvisoryRelaxesOnlyInstallerOwnedPaths(t *testing.T) {
	advisoryLogDedupe.reset()
	t.Cleanup(func() { advisoryLogDedupe.reset() })
	t.Setenv(TrustStrictAncestorsEnv, "")

	runtimeDir := filepath.Join(PlatformInstallerOwnedRoots()[0], "secureclient", "defenseclaw", "runtime")
	if !managedModeAdvisory(runtimeDir, "private directory permissions are too broad") {
		t.Fatalf("managedModeAdvisory(%s) = false, want true for an installer-owned path", runtimeDir)
	}
	outside := filepath.Join(t.TempDir(), "runtime")
	if managedModeAdvisory(outside, "private directory permissions are too broad") {
		t.Fatalf("managedModeAdvisory(%s) = true, want false outside the installer-owned roots", outside)
	}

	t.Setenv(TrustStrictAncestorsEnv, "1")
	if managedModeAdvisory(runtimeDir, "private directory permissions are too broad") {
		t.Fatalf("managedModeAdvisory(%s) = true with %s=1, want false", runtimeDir, TrustStrictAncestorsEnv)
	}
}
