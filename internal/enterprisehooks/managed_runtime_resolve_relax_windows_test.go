// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

type windowsRelaxResolveFixture struct {
	dataDir string
	hookDir string
	target  *windows.SID
	desired WindowsManagedRuntimeGenerationDesired
	resolve WindowsManagedRuntimeGenerationResolveOptions
	first   WindowsManagedRuntimeGenerationPublication
}

// newWindowsRelaxResolveFixture publishes one selected codex generation for
// the current account in canonical <data dir> and <data dir>\hooks folders.
func newWindowsRelaxResolveFixture(t *testing.T) windowsRelaxResolveFixture {
	t.Helper()
	base := t.TempDir()
	dataDir := filepath.Join(base, ".defenseclaw")
	hookDir := filepath.Join(dataDir, "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := currentWindowsTestSID(t)
	for _, path := range []string{dataDir, hookDir} {
		// The guardian relaxes only folders the account owns.
		setWindowsTestPathExactOwner(t, path, target)
		if err := setWindowsUserPathProtection(path, target, true); err != nil {
			t.Fatalf("protect target directory %s: %v", path, err)
		}
	}
	selectorPath := filepath.Join(base, windowsManagedRuntimeSelectorFile)
	originalPath := windowsManagedRuntimeSelectorPathResolver
	originalOwner := windowsManagedPolicyOwnerSID
	originalDirTrust := windowsManagedPolicyDirTrustCheck
	originalAncestorTrust := windowsManagedPolicyAncestorTrustCheck
	originalFileTrust := windowsManagedPolicyFileTrustCheck
	originalMutation := windowsManagedRuntimeSelectorMutationAuthorize
	originalVerifyAuthorize := windowsManagedRuntimeSelectorVerifyAuthorize
	originalHookTrust := windowsEnterpriseHookTrustCheck
	windowsManagedRuntimeSelectorPathResolver = func(string) (string, error) { return selectorPath, nil }
	windowsManagedPolicyOwnerSID = func() (*windows.SID, error) { return target, nil }
	windowsManagedPolicyDirTrustCheck = func(string) error { return nil }
	windowsManagedPolicyAncestorTrustCheck = func(string) error { return nil }
	windowsManagedPolicyFileTrustCheck = func(string) error { return nil }
	windowsManagedRuntimeSelectorMutationAuthorize = func() error { return nil }
	windowsManagedRuntimeSelectorVerifyAuthorize = func() error { return nil }
	windowsEnterpriseHookTrustCheck = func(string) error { return nil }
	t.Cleanup(func() {
		windowsManagedRuntimeSelectorPathResolver = originalPath
		windowsManagedPolicyOwnerSID = originalOwner
		windowsManagedPolicyDirTrustCheck = originalDirTrust
		windowsManagedPolicyAncestorTrustCheck = originalAncestorTrust
		windowsManagedPolicyFileTrustCheck = originalFileTrust
		windowsManagedRuntimeSelectorMutationAuthorize = originalMutation
		windowsManagedRuntimeSelectorVerifyAuthorize = originalVerifyAuthorize
		windowsEnterpriseHookTrustCheck = originalHookTrust
	})
	now := time.Now().UTC().Format(time.RFC3339Nano)
	desired := WindowsManagedRuntimeGenerationDesired{
		Connector:                  "codex",
		TargetSID:                  target.String(),
		DataDir:                    dataDir,
		HookExecutable:             filepath.Join(base, "defenseclaw-hook.exe"),
		GatewayAddr:                "127.0.0.1:18970",
		GatewayServiceName:         "DefenseClawGateway",
		ScopedToken:                "scoped-test-token",
		HookContractID:             "codex-hooks-v1",
		HookContractLockUpdatedAt:  now,
		HookContractEntryUpdatedAt: now,
	}
	first, err := PrepareWindowsManagedRuntimeGeneration(desired)
	if err != nil {
		t.Fatalf("prepare generation: %v", err)
	}
	if _, err := CommitWindowsManagedRuntimeGeneration(first); err != nil {
		t.Fatalf("commit generation: %v", err)
	}
	return windowsRelaxResolveFixture{
		dataDir: dataDir,
		hookDir: hookDir,
		target:  target,
		desired: desired,
		resolve: WindowsManagedRuntimeGenerationResolveOptions{
			Connector:               desired.Connector,
			TargetSID:               desired.TargetSID,
			DataDir:                 desired.DataDir,
			HookExecutable:          desired.HookExecutable,
			MachinePolicyRegistered: true,
		},
		first: first,
	}
}

// setWindowsRelaxTestDACL gives path the protected DACL sddl, keeping its owner.
func setWindowsRelaxTestDACL(t *testing.T, path, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	protection := uint32(windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if strings.HasPrefix(sddl, "D:(") {
		protection = windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.SECURITY_INFORMATION(protection),
		nil, nil, dacl, nil); err != nil {
		t.Fatalf("set DACL %s on %s: %v", sddl, path, err)
	}
}

// GAP-1502: a guardian repair of one per-user connector relaxes <data dir>
// (Hermes) and <data dir>\hooks to the owner-private setup DACL while the
// connector's setup runs (about a third of a second live), then hardens them
// again. Every managed hook of that account resolving meanwhile, all five
// routes, was refused as "not set up correctly" with no gateway call. The
// resolver now waits out that exact shape and resolves the selected
// generation once the guardian has put the canonical DACL back.
func TestWindowsManagedRuntimeResolveWaitsOutGuardianSetupRelax(t *testing.T) {
	for _, tc := range []struct {
		name string
		pick func(windowsRelaxResolveFixture) []string
	}{
		{"data dir", func(f windowsRelaxResolveFixture) []string { return []string{f.dataDir} }},
		{"hooks dir", func(f windowsRelaxResolveFixture) []string { return []string{f.hookDir} }},
		{"both", func(f windowsRelaxResolveFixture) []string { return []string{f.dataDir, f.hookDir} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newWindowsRelaxResolveFixture(t)
			relaxed := tc.pick(fixture)
			for _, path := range relaxed {
				setWindowsRelaxTestDACL(t, path, windowsSetupRelaxedDirectorySDDL)
			}
			hardened := make(chan error, 1)
			go func() {
				time.Sleep(300 * time.Millisecond)
				var err error
				for index := len(relaxed) - 1; index >= 0; index-- {
					err = errors.Join(err, setWindowsUserPathProtection(relaxed[index], fixture.target, true))
				}
				hardened <- err
			}()
			runtime, err := ResolveWindowsManagedRuntimeGeneration(fixture.resolve)
			if hardenErr := <-hardened; hardenErr != nil {
				t.Fatalf("restore canonical DACL: %v", hardenErr)
			}
			if err != nil {
				t.Fatalf("resolve during a guardian setup relax was refused: %v", err)
			}
			if runtime.GenerationID != fixture.first.GenerationID() || runtime.ScopedToken() != fixture.desired.ScopedToken {
				t.Fatalf("resolved generation %q, want %q", runtime.GenerationID, fixture.first.GenerationID())
			}
		})
	}
}
