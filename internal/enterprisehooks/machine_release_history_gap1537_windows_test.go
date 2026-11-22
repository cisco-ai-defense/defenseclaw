// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// GAP-1537, GAP-0644 (review RV-W111G): the other-release sign-in waits, the
// Hermes earlier-matrix wait among them, trusted the defenseclaw_version of
// the target's hook-contract lock. The lock is in the account's own
// DefenseClaw folder, which the account owns and can write, so an account
// that edited it in place to an older release (owner and access list
// unchanged) turned its own tampering into "pending". The release a lock
// names now counts only when the administrator-only machine release history
// beside the deployment record names it, on the standalone profile, whose
// deployment record names its release. An upgrade from 1.0.3, whose
// signed-out Hermes accounts still wait, has 1.0.3 in it. Fails on
// d36e4f852b: the edited lock read as another release.
//
// GAP-1762: Secure Client deployment records name no release, so Setup keeps
// no history there, and f29b6f6617 failed every Secure Client other-release
// wait, a legit upgrade with a signed-out account included. On Secure Client
// the lock's release counts without a history; the guardian binds it to the
// target instead (internal/cli TestGAP1762OtherReleaseWaitIsBoundToTheTarget:
// no wait for a target this release already protected, on both profiles).
// Fails on f29b6f6617: the Secure Client lock read as no other release.
func TestGAP1537AccountEditedLockReleaseNeedsTheMachineReleaseHistory(t *testing.T) {
	// The account folders get their owner with the setup privilege and the
	// history file an Administrators owner, which only an elevated token can
	// set.
	requireGAP633Elevated(t)
	gap45AllowMutation(t)
	previousStandalone := windowsEnterpriseStandaloneProcess
	t.Cleanup(func() { windowsEnterpriseStandaloneProcess = previousStandalone })
	windowsEnterpriseStandaloneProcess = func() bool { return true }
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
	this := version.Current().BinaryVersion
	if err := connector.SaveHookContractLockEntryForMode(dataDir, connector.HookContractLockEntry{
		Connector: "codex", RawAgentVersion: "1", ContractID: "codex-hooks-v1", HookFailMode: "closed",
		ManagedGatewayServiceName: "DefenseClawGateway", DefenseClawVersion: this,
	}, true); err != nil {
		t.Fatalf("save the lock: %v", err)
	}
	// The account edits its own lock in place: an ordinary write keeps the
	// file's owner and access list, so every shape check still passes.
	lockPath := filepath.Join(dataDir, "hook_contract_lock.json")
	body, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatalf("read the lock: %v", err)
	}
	var document any
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatalf("parse the lock: %v", err)
	}
	if edited := gap1537SetLockRelease(document, "1.0.3"); edited == 0 {
		t.Fatalf("the lock has no defenseclaw_version to edit: %s", body)
	}
	forged, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockPath, forged, 0o600); err != nil {
		t.Fatalf("the account edits its lock: %v", err)
	}

	stateRoot := t.TempDir()
	install := filepath.Join(stateRoot, "install")
	if err := os.MkdirAll(install, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, filepath.Join(stateRoot, "hook-guardian-state"))
	historyPath := filepath.Join(install, "release_history.json")
	adminOnly := "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
	writeHistory := func(sddl string, releases ...string) {
		t.Helper()
		_ = os.Remove(historyPath)
		body, err := json.Marshal(map[string]any{"schema_version": 1, "releases": releases})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(historyPath, body, 0o600); err != nil {
			t.Fatal(err)
		}
		gap1537SetSDDL(t, historyPath, sddl)
	}
	opts := InstallOptions{ConnectorName: "codex", UserHome: home, OwnerSID: sid.String()}
	check := func(label, wantWritten string, wantOther, wantErr bool) {
		t.Helper()
		written, other, err := WindowsProtectedTargetFromOtherRelease(opts)
		if other != wantOther || written != wantWritten || (err != nil) != wantErr {
			t.Fatalf("%s: written=%q other=%t err=%v; want written=%q other=%t error=%t",
				label, written, other, err, wantWritten, wantOther, wantErr)
		}
	}

	writeHistory(adminOnly, "1.0.10")
	check("a lock the account edited to 1.0.3 on a computer that ran only 1.0.10", "", false, false)
	_ = os.Remove(historyPath)
	check("a lock the account edited to 1.0.3 with no machine release history", "", false, false)
	// The test account is an elevated administrator, so a standard user's
	// write grant stands for the signed-out account's.
	writeHistory("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;BU)", "1.0.3")
	check("a release history standard users can write", "", false, true)
	writeHistory(adminOnly, "1.0.3", "1.0.10")
	check("an upgrade from 1.0.3 with the account still signed out", "1.0.3", true, false)
	writeHistory(adminOnly, "v1.0.3")
	check("a recorded release with a leading v", "1.0.3", true, false)

	// Secure Client: no history; the lock's release is another release.
	windowsEnterpriseStandaloneProcess = func() bool { return false }
	_ = os.Remove(historyPath)
	check("GAP-1762: a Secure Client upgrade with no machine release history", "1.0.3", true, false)
	writeHistory(adminOnly, "1.0.10")
	check("GAP-1762: a Secure Client upgrade ignores the history", "1.0.3", true, false)
}

// gap1537SetLockRelease sets every defenseclaw_version in a decoded lock and
// returns how many it set.
func gap1537SetLockRelease(node any, release string) int {
	set := 0
	switch value := node.(type) {
	case map[string]any:
		for key, child := range value {
			if key == "defenseclaw_version" {
				value[key] = release
				set++
				continue
			}
			set += gap1537SetLockRelease(child, release)
		}
	case []any:
		for _, child := range value {
			set += gap1537SetLockRelease(child, release)
		}
	}
	return set
}

func gap1537SetSDDL(t *testing.T, path, sddl string) {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil); err != nil {
		t.Fatalf("set the access list of %s: %v", path, err)
	}
}
