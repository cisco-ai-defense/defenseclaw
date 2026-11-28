// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// GAP-1096 (cert replay on IB4): an administrator who went back to 1.0.9 ran
// hook-image retire first, so this release guardian rewrote every account
// record for the transition image bin\defenseclaw-hook.exe and wrote the
// hook-contract lock as this release. 1.0.9 accepts that render and leaves
// the lock as it is. The upgrade back to this release then found every
// account with no active session failed: its lock names this release, so the
// release check said "not from another release" and the read-only proof that
// accepts the recorded earlier image never ran. A lock this release wrote is
// a retire render when the protected runtime selector records an earlier
// trusted image of this install for the SID; any other lock this release wrote
// is not. The release check itself stays as it was (review RV-LENT P2-1): a
// retire render is never "another release" for the other sign-in waits.
func TestWindowsProtectedTargetRetireRenderTakesThisReleaseRetireRender(t *testing.T) {
	// The fixture gives the account folders their owner with the setup
	// privilege (gap45Own), which only an elevated token holds.
	requireGAP633Elevated(t)
	gap45AllowMutation(t)
	sid := currentWindowsTestSID(t)
	home := newWindowsTargetOwnedTestHome(t, sid)
	dataDir := filepath.Join(home, ".defenseclaw")
	hookDir := filepath.Join(dataDir, "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	gap45Own(t, sid, dataDir, hookDir)
	for _, path := range []string{dataDir, hookDir} {
		if err := setWindowsUserPathProtection(path, sid, true); err != nil {
			t.Fatalf("protect %s: %v", path, err)
		}
	}
	base := t.TempDir()
	bin := filepath.Join(base, "bin")
	transition := filepath.Join(bin, "defenseclaw-hook.exe")
	launch := filepath.Join(bin, "hooks", "0123456789abcdef", "defenseclaw-hook.exe")
	if err := os.MkdirAll(filepath.Dir(launch), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, image := range []string{transition, launch} {
		if err := os.WriteFile(image, []byte("hook"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	current := launch
	selectorPath := filepath.Join(base, windowsManagedRuntimeSelectorFile)
	restore := []func(){}
	swap := func(set, reset func()) { set(); restore = append(restore, reset) }
	t.Cleanup(func() {
		for i := len(restore) - 1; i >= 0; i-- {
			restore[i]()
		}
	})
	prevStandalone, prevHook, prevTrust := windowsEnterpriseStandaloneProcess, windowsEnterpriseHookExecutable, windowsEnterpriseHookTrustCheck
	swap(func() {
		windowsEnterpriseStandaloneProcess = func() bool { return true }
		windowsEnterpriseHookExecutable = func() (string, error) { return current, nil }
		windowsEnterpriseHookTrustCheck = func(string) error { return nil }
	}, func() {
		windowsEnterpriseStandaloneProcess, windowsEnterpriseHookExecutable, windowsEnterpriseHookTrustCheck = prevStandalone, prevHook, prevTrust
	})
	prevPath, prevOwner := windowsManagedRuntimeSelectorPathResolver, windowsManagedPolicyOwnerSID
	prevDir, prevAncestor, prevFile := windowsManagedPolicyDirTrustCheck, windowsManagedPolicyAncestorTrustCheck, windowsManagedPolicyFileTrustCheck
	prevMutation, prevVerify := windowsManagedRuntimeSelectorMutationAuthorize, windowsManagedRuntimeSelectorVerifyAuthorize
	swap(func() {
		windowsManagedRuntimeSelectorPathResolver = func(string) (string, error) { return selectorPath, nil }
		windowsManagedPolicyOwnerSID = func() (*windows.SID, error) { return sid, nil }
		windowsManagedPolicyDirTrustCheck = func(string) error { return nil }
		windowsManagedPolicyAncestorTrustCheck = func(string) error { return nil }
		windowsManagedPolicyFileTrustCheck = func(string) error { return nil }
		windowsManagedRuntimeSelectorMutationAuthorize = func() error { return nil }
		windowsManagedRuntimeSelectorVerifyAuthorize = func() error { return nil }
	}, func() {
		windowsManagedRuntimeSelectorPathResolver, windowsManagedPolicyOwnerSID = prevPath, prevOwner
		windowsManagedPolicyDirTrustCheck, windowsManagedPolicyAncestorTrustCheck, windowsManagedPolicyFileTrustCheck = prevDir, prevAncestor, prevFile
		windowsManagedRuntimeSelectorMutationAuthorize, windowsManagedRuntimeSelectorVerifyAuthorize = prevMutation, prevVerify
	})

	this := version.Current().BinaryVersion
	saveLock := func(written string) {
		t.Helper()
		if err := connector.SaveHookContractLockEntryForMode(dataDir, connector.HookContractLockEntry{
			Connector: "codex", RawAgentVersion: "1", ContractID: "codex-hooks-v1", HookFailMode: "closed",
			ManagedGatewayServiceName: "DefenseClawGateway", DefenseClawVersion: written,
		}, true); err != nil {
			t.Fatalf("save the lock: %v", err)
		}
	}
	saveLock(this)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	publication, err := PrepareWindowsManagedRuntimeGeneration(WindowsManagedRuntimeGenerationDesired{
		Connector: "codex", TargetSID: sid.String(), DataDir: dataDir, HookExecutable: transition,
		GatewayAddr: "127.0.0.1:18970", GatewayServiceName: "DefenseClawGateway", ScopedToken: "scoped-test-token",
		HookContractID: "codex-hooks-v1", HookContractLockUpdatedAt: now, HookContractEntryUpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("prepare the retire generation: %v", err)
	}
	if _, err := CommitWindowsManagedRuntimeGeneration(publication); err != nil {
		t.Fatalf("commit the retire generation: %v", err)
	}

	opts := InstallOptions{ConnectorName: "codex", UserHome: home, OwnerSID: sid.String()}
	check := func(label, wantOtherWritten string, wantOther bool, wantRetireWritten string, wantRetire bool) {
		t.Helper()
		written, other, err := WindowsProtectedTargetFromOtherRelease(opts)
		if err != nil || other != wantOther || written != wantOtherWritten {
			t.Fatalf("%s: other release written=%q other=%t err=%v; want written=%q other=%t", label, written, other, err, wantOtherWritten, wantOther)
		}
		written, retire, err := WindowsProtectedTargetRetireRender(opts)
		if err != nil || retire != wantRetire || written != wantRetireWritten {
			t.Fatalf("%s: retire render written=%q retire=%t err=%v; want written=%q retire=%t", label, written, retire, err, wantRetireWritten, wantRetire)
		}
	}
	check("this release retire render of the transition image", "", false, this, true)

	current = transition
	check("this release render of the image it runs", "", false, "", false)
	current = launch

	windowsEnterpriseHookTrustCheck = func(path string) error {
		if path == transition {
			return errors.New("untrusted")
		}
		return nil
	}
	check("an untrusted recorded image", "", false, "", false)
	windowsEnterpriseHookTrustCheck = func(string) error { return nil }

	saveLock("1.0.9")
	stateRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(stateRoot, "install"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, filepath.Join(stateRoot, "hook-guardian-state"))
	check("a lock 1.0.9 wrote with no machine release history (GAP-1537)", "", false, "", false)
	history := filepath.Join(stateRoot, "install", "release_history.json")
	if err := os.WriteFile(history, []byte(`{"schema_version":1,"releases":["1.0.9"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	gap1537SetSDDL(t, history, "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)")
	check("a lock 1.0.9 wrote on a computer that ran 1.0.9", "1.0.9", true, "", false)
}
