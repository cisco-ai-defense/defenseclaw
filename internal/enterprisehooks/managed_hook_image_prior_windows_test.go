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

// GAP-1096: a 1.0.9 target keeps its runtime selector entry and bundle for the
// transition image bin\defenseclaw-hook.exe while its account has no active
// Windows session through the upgrade to the 1.0.10 launch image. The exact
// verification fails it ("selector does not match the verified target"); the
// read-only verification that accepts an earlier release render checks it
// against the image it records, and only that: an image of this install that
// is a trusted regular file, never in any other verification.
func TestWindowsPriorReleaseTargetHookImageAcceptsTheRecordedTransitionImage(t *testing.T) {
	base := t.TempDir()
	dataDir := filepath.Join(base, ".defenseclaw")
	hookDir := filepath.Join(dataDir, "hooks")
	bin := filepath.Join(base, "bin")
	transition := filepath.Join(bin, "defenseclaw-hook.exe")
	launch := filepath.Join(bin, "hooks", "0123456789abcdef", "defenseclaw-hook.exe")
	for _, dir := range []string{hookDir, filepath.Dir(launch)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, image := range []string{transition, launch} {
		if err := os.WriteFile(image, []byte("hook"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	target := currentWindowsTestSID(t)
	for _, path := range []string{dataDir, hookDir} {
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
	recorded := WindowsManagedRuntimeGenerationDesired{
		Connector:                  "codex",
		TargetSID:                  target.String(),
		DataDir:                    dataDir,
		HookExecutable:             transition,
		GatewayAddr:                "127.0.0.1:18970",
		GatewayServiceName:         "DefenseClawGateway",
		ScopedToken:                "scoped-test-token",
		HookContractID:             "codex-hooks-v1",
		HookContractLockUpdatedAt:  now,
		HookContractEntryUpdatedAt: now,
	}
	publication, err := PrepareWindowsManagedRuntimeGeneration(recorded)
	if err != nil {
		t.Fatalf("prepare the 1.0.9 generation: %v", err)
	}
	if _, err := CommitWindowsManagedRuntimeGeneration(publication); err != nil {
		t.Fatalf("commit the 1.0.9 generation: %v", err)
	}

	current := recorded
	current.HookExecutable = launch
	if err := windowsManagedRuntimeGenerationVerify(current); err == nil ||
		!strings.Contains(err.Error(), "selector does not match the verified target") {
		t.Fatalf("exact verify against the launch image = %v, want the selector mismatch of GAP-1096", err)
	}

	prior := InstallOptions{AcceptPriorReleaseRender: true}
	image := windowsPriorReleaseTargetHookImage(prior, "codex", target, launch)
	if image != transition {
		t.Fatalf("prior-release image = %q, want the recorded transition image %q", image, transition)
	}
	current.HookExecutable = image
	if err := windowsManagedRuntimeGenerationVerify(current); err != nil {
		t.Fatalf("verify against the recorded image: %v", err)
	}

	if got := windowsPriorReleaseTargetHookImage(InstallOptions{}, "codex", target, launch); got != launch {
		t.Fatalf("an ordinary verify uses %q, want the current image", got)
	}
	other := filepath.Join(base, "other", "bin", "hooks", "0123456789abcdef", "defenseclaw-hook.exe")
	if got := windowsPriorReleaseTargetHookImage(prior, "codex", target, other); got != other {
		t.Fatalf("an image of another install bin was taken: %q", got)
	}
	windowsEnterpriseHookTrustCheck = func(path string) error {
		if path == transition {
			return errors.New("untrusted")
		}
		return nil
	}
	if got := windowsPriorReleaseTargetHookImage(prior, "codex", target, launch); got != launch {
		t.Fatalf("an untrusted recorded image was taken: %q", got)
	}
	windowsEnterpriseHookTrustCheck = func(string) error { return nil }
	if err := os.Remove(transition); err != nil {
		t.Fatal(err)
	}
	if got := windowsPriorReleaseTargetHookImage(prior, "codex", target, launch); got != launch {
		t.Fatalf("a missing recorded image was taken: %q", got)
	}
	other2, _ := windows.StringToSid("S-1-5-21-1-2-3-4242")
	if got := windowsPriorReleaseTargetHookImage(prior, "codex", other2, launch); got != launch {
		t.Fatalf("a SID the selector does not name took %q", got)
	}
}
