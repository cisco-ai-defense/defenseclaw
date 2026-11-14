// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// A launch image under bin\hooks\<16 hex> is the standalone managed hook as
// the transition image is (GAP-0751): an agent session that read its command
// before an upgrade starts an earlier launch image and must never fall back
// to the per-user runtime. Only the hook of a launch folder of a validated
// root counts.
func TestStandaloneEnterpriseHookExecutableAdmitsLaunchImages(t *testing.T) {
	roots, err := windowsManagedLayout.roots(winpath.EnterpriseProfileStandalone)
	if err != nil {
		t.Skipf("trusted enterprise roots unavailable: %v", err)
	}
	secureClient, err := winpath.TrustedEnterpriseRoots(winpath.EnterpriseProfileSecureClient)
	if err != nil {
		t.Skipf("trusted Secure Client roots unavailable: %v", err)
	}
	launch := func(root, folder, name string) string {
		return filepath.Join(root, "bin", "hooks", folder, name)
	}
	for path, want := range map[string]bool{
		launch(roots.InstallRoot, "0123456789abcdef", "defenseclaw-hook.exe"):                                           true,
		launch(roots.InstallRoot, "aaaaaaaaaaaaaaaa", "defenseclaw-hook.exe"):                                           true,
		launch(filepath.Join(roots.CertificationInstallBase, "0123456789"), "0123456789abcdef", "defenseclaw-hook.exe"): true,
		launch(roots.InstallRoot, "0123456789abcdef", "defenseclaw-hook-guard.exe"):                                     false,
		launch(roots.InstallRoot, ".staging-0123456789abcdef", "defenseclaw-hook.exe"):                                  false,
		launch(roots.InstallRoot, "0123456789abcde", "defenseclaw-hook.exe"):                                            false,
		filepath.Join(roots.InstallRoot, "bin", "hooks", "defenseclaw-hook.exe"):                                        false,
		launch(secureClient.InstallRoot, "0123456789abcdef", "defenseclaw-hook.exe"):                                    false,
		filepath.Join(roots.InstallRoot, "libexec", "hooks", "0123456789abcdef", "defenseclaw-hook.exe"):                false,
	} {
		if got := standaloneEnterpriseHookExecutable(path); got != want {
			t.Errorf("standaloneEnterpriseHookExecutable(%q) = %t, want %t", path, got, want)
		}
	}
}
