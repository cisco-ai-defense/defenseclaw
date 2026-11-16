// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"path/filepath"
	"runtime"
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

// GAP-0026: only the Secure Client install keeps the earlier write-bit
// advisory; the standalone install below the same roots does not.
func TestSecureClientInstallPathCoversOnlyTheSecureClientTree(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("safefile mode-bit verdicts and these install paths are Unix-only")
	}
	if safefile.ManagedWriteModeAdvisory == nil {
		t.Fatal("safefile.ManagedWriteModeAdvisory is nil; the managed package must install it")
	}
	for path, want := range map[string]bool{
		"/opt/cisco/secureclient/defenseclaw/runtime": true,
		"/opt/cisco/secureclient":                     true,
		"/opt/cisco/defenseclaw/runtime":              false,
		"/opt/cisco/secureclientx":                    false,
		"/Library/Logs/Cisco/DefenseClaw":             false,
		"":                                            false,
	} {
		if got := secureClientInstallPath(path); got != want {
			t.Errorf("secureClientInstallPath(%q) = %v, want %v", path, got, want)
		}
	}
}
