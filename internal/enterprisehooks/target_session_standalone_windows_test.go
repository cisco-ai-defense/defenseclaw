// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// deferredPendingProofFixture is a real deferred row for a profile that
// DefenseClaw has never touched: the home exists, its canonical
// %USERPROFILE%\.defenseclaw does not, and no runtime selector is published.
func deferredPendingProofFixture(t *testing.T, standalone bool) ManifestTarget {
	t.Helper()
	targetSID := currentWindowsTestSID(t)
	home := newWindowsTargetOwnedTestHome(t, targetSID)
	// The trust check is stubbed; the proof only needs a canonical path.
	hookExe := filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
	selectorRoot := t.TempDir()

	previousStandalone := windowsEnterpriseStandaloneProcess
	previousHook := windowsEnterpriseHookExecutable
	previousTrust := windowsEnterpriseHookTrustCheck
	previousSelector := windowsManagedRuntimeSelectorPathResolver
	windowsEnterpriseStandaloneProcess = func() bool { return standalone }
	windowsEnterpriseHookExecutable = func() (string, error) { return hookExe, nil }
	windowsEnterpriseHookTrustCheck = func(string) error { return nil }
	windowsManagedRuntimeSelectorPathResolver = func(name string) (string, error) {
		return filepath.Join(selectorRoot, name, windowsManagedRuntimeSelectorFile), nil
	}
	t.Cleanup(func() {
		windowsEnterpriseStandaloneProcess = previousStandalone
		windowsEnterpriseHookExecutable = previousHook
		windowsEnterpriseHookTrustCheck = previousTrust
		windowsManagedRuntimeSelectorPathResolver = previousSelector
	})

	enabled := true
	return ManifestTarget{
		SID:          targetSID.String(),
		UserHome:     home,
		Connector:    "claudecode",
		AgentVersion: "2.1.230",
		Enabled:      &enabled,
		Deferred:     true,
	}
}

// An account that ran an agent before it was enrolled has a
// %USERPROFILE%\.defenseclaw the hook created with the profile's inherited
// DACL. The pending proof must accept it, and enrollment in the account's
// session must adopt it instead of failing every reconcile.
func TestStandaloneDeferredPendingProofAndEnrollmentAdoptAnAccountCreatedDataDirectory(t *testing.T) {
	target := deferredPendingProofFixture(t, true)
	sid := currentWindowsTestSID(t)
	dataDir := filepath.Join(target.UserHome, ".defenseclaw")
	// A junction the account made there, to another folder it owns, is not one.
	elsewhere := filepath.Join(target.UserHome, "elsewhere")
	if err := os.MkdirAll(elsewhere, 0o700); err != nil {
		t.Fatal(err)
	}
	setWindowsTestPathExactOwner(t, elsewhere, sid)
	if output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", dataDir, elsewhere).CombinedOutput(); err != nil {
		t.Fatalf("create junction: %v: %s", err, output)
	}
	setWindowsTestPathExactOwner(t, dataDir, sid)
	if err := RequireWindowsEnterpriseDeferredTargetPending(target); err == nil {
		t.Fatal("the pending proof accepted a junctioned data directory")
	}
	if err := os.Remove(dataDir); err != nil {
		t.Fatal(err)
	}
	logs := filepath.Join(dataDir, "logs")
	if err := os.MkdirAll(logs, 0o700); err != nil {
		t.Fatal(err)
	}
	record := filepath.Join(logs, "hook-failures.jsonl")
	if err := os.WriteFile(record, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dataDir, logs, record} {
		setWindowsTestPathExactOwner(t, path, sid)
	}
	if err := RequireWindowsEnterpriseDeferredTargetPending(target); err != nil {
		t.Fatalf("pending proof for an account-created data directory failed: %v", err)
	}
	// Repair plans the account's root pending and the lifecycle retire finds
	// nothing to retire there, instead of failing the whole lifecycle.
	plan, err := PlanWindowsManagedRuntimeRootsForValidation(
		Manifest{Version: 1, Targets: []ManifestTarget{target}},
		`C:\ProgramData\DefenseClaw\etc\targets.yaml`,
		strings.Repeat("a", 64),
	)
	if err != nil || len(plan.Roots) != 1 || plan.Roots[0].Baseline != windowsManagedRuntimeBaselinePending {
		t.Fatalf("repair plan = %+v, %v; want the account's root pending", plan.Roots, err)
	}
	hookExe, _ := windowsEnterpriseHookExecutable()
	previousAncestor, previousDir, previousFile := windowsManagedPolicyAncestorTrustCheck, windowsManagedPolicyDirTrustCheck, windowsManagedPolicyFileTrustCheck
	windowsManagedPolicyAncestorTrustCheck = func(string) error { return nil }
	windowsManagedPolicyDirTrustCheck = func(string) error { return nil }
	windowsManagedPolicyFileTrustCheck = func(string) error { return nil }
	previousOwner, previousMutation := windowsManagedPolicyOwnerSID, windowsManagedRuntimeSelectorMutationAuthorize
	windowsManagedPolicyOwnerSID = func() (*windows.SID, error) { return sid, nil }
	windowsManagedRuntimeSelectorMutationAuthorize = func() error { return nil }
	t.Cleanup(func() {
		windowsManagedPolicyAncestorTrustCheck, windowsManagedPolicyDirTrustCheck, windowsManagedPolicyFileTrustCheck = previousAncestor, previousDir, previousFile
		windowsManagedPolicyOwnerSID, windowsManagedRuntimeSelectorMutationAuthorize = previousOwner, previousMutation
	})
	retire := func() (int, error) {
		return GarbageCollectWindowsManagedRuntimeGenerations(WindowsManagedRuntimeGenerationGCOptions{
			Connector:      "claudecode",
			TargetSID:      sid.String(),
			DataDir:        dataDir,
			HookExecutable: hookExe,
		})
	}
	if removed, err := retire(); err != nil || removed != 0 {
		t.Fatalf("lifecycle retire = %d, %v; want nothing to retire", removed, err)
	}
	// Nor for an enrolled account that moved DefenseClaw's folder away and
	// made a new one: its selected generation left with the moved folder.
	selectorPath, err := windowsManagedRuntimeSelectorPath("claudecode")
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureWindowsManagedPolicyDirectory(filepath.Dir(selectorPath)); err != nil {
		t.Fatal(err)
	}
	if err := publishWindowsManagedRuntimeSelector(windowsManagedRuntimeSelector{
		SchemaVersion: windowsManagedRuntimeGenerationSchema,
		Connector:     "claudecode",
		Targets: []windowsManagedRuntimeSelectorTarget{{
			Connector: "claudecode", SID: sid.String(), DataDir: dataDir, HookExecutable: hookExe,
			GatewayAddr: "127.0.0.1:18970", GatewayServiceName: "DefenseClawGateway",
			GenerationID: strings.Repeat("a", 32), BundleSHA256: "sha256:" + strings.Repeat("b", 64),
		}},
	}); err != nil {
		t.Fatalf("publish the account's selected generation: %v", err)
	}
	if removed, err := retire(); err != nil || removed != 0 {
		t.Fatalf("lifecycle retire with a selected generation = %d, %v; want nothing to retire", removed, err)
	}
	var creation windowsTargetOwnedDirectoryCreation
	if err := runWindowsTestThreadImpersonatedAsSelf(func() error {
		var err error
		creation, err = ensureWindowsTargetOwnedDirectoryTree(target.UserHome, filepath.Join(dataDir, "hooks"), sid)
		return err
	}); err != nil {
		t.Fatalf("enrollment did not adopt the account-created data directory: %v", err)
	}
	if creation.createdDataDir || !creation.createdHookDir {
		t.Fatalf("adoption creation = %+v, want only the hook directory created", creation)
	}
	assertWindowsTargetOwnedCanonicalDirectory(t, dataDir, sid)
	if _, err := os.Lstat(record); err != nil {
		t.Fatalf("adoption must keep the account's own files: %v", err)
	}
}

// The pending proof for a deferred row of a profile DefenseClaw never
// touched: on the standalone profile an absent data directory is accepted,
// while a file in its place or a published runtime selector is refused; the
// Secure Client profile still requires the data directory.
func TestDeferredPendingProofForAnUntouchedProfile(t *testing.T) {
	for _, tc := range []struct {
		name       string
		standalone bool
		prepare    func(t *testing.T, target ManifestTarget)
		want       string // the refusal; "" accepts unless refused is set
		refused    bool
	}{
		{name: "standalone, absent data directory", standalone: true, prepare: func(t *testing.T, target ManifestTarget) {
			if _, err := os.Lstat(filepath.Join(target.UserHome, ".defenseclaw")); !os.IsNotExist(err) {
				t.Fatalf("fixture data directory must be absent, got %v", err)
			}
		}},
		{name: "secure client", want: "deferred target data directory is untrusted"},
		{name: "standalone, file in place of the data directory", standalone: true, want: "deferred target data directory is untrusted",
			prepare: func(t *testing.T, target ManifestTarget) {
				if err := os.WriteFile(filepath.Join(target.UserHome, ".defenseclaw"), []byte("not a directory"), 0o600); err != nil {
					t.Fatal(err)
				}
			}},
		// Any published selector must be read and judged; an unreadable one
		// is an error, never proof of absence.
		{name: "standalone, selector published", standalone: true, refused: true,
			prepare: func(t *testing.T, _ ManifestTarget) {
				selector, err := windowsManagedRuntimeSelectorPathResolver("claudecode")
				if err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(filepath.Dir(selector), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(selector, []byte("{"), 0o600); err != nil {
					t.Fatal(err)
				}
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := deferredPendingProofFixture(t, tc.standalone)
			if tc.prepare != nil {
				tc.prepare(t, target)
			}
			err := RequireWindowsEnterpriseDeferredTargetPending(target)
			switch {
			case tc.refused:
				if err == nil {
					t.Fatal("pending proof accepted a profile while a runtime selector was published")
				}
			case tc.want == "":
				if err != nil {
					t.Fatalf("pending proof: %v", err)
				}
			case err == nil || !strings.Contains(err.Error(), tc.want):
				t.Fatalf("pending proof error = %v, want %q", err, tc.want)
			}
		})
	}
}

// GAP-0262: revoking a user narrowed only the primary machine policy and left
// the user's runtime selection, so once the user was enrolled again the
// deferred pending proof refused the row and every later Setup /ensure
// failed. The guardian retires the selection of a SID the machine policy no
// longer registers; a registered SID's selection and another deployment's
// stay, and the proof still refuses them. GAP-0271: a pass reads each
// connector's machine policy once, not once per selection.
func TestStandaloneGuardianRetiresTheRuntimeSelectionOfAnUnregisteredUser(t *testing.T) {
	target := deferredPendingProofFixture(t, true)
	sid := currentWindowsTestSID(t)
	hookExe, _ := windowsEnterpriseHookExecutable()
	previousAncestor, previousDir, previousFile := windowsManagedPolicyAncestorTrustCheck, windowsManagedPolicyDirTrustCheck, windowsManagedPolicyFileTrustCheck
	previousOwner, previousMutation := windowsManagedPolicyOwnerSID, windowsManagedRuntimeSelectorMutationAuthorize
	previousRegistered := windowsMachinePolicyRegisteredSIDs
	windowsManagedPolicyAncestorTrustCheck = func(string) error { return nil }
	windowsManagedPolicyDirTrustCheck = func(string) error { return nil }
	windowsManagedPolicyFileTrustCheck = func(string) error { return nil }
	windowsManagedPolicyOwnerSID = func() (*windows.SID, error) { return sid, nil }
	windowsManagedRuntimeSelectorMutationAuthorize = func() error { return nil }
	const peerSID = "S-1-5-21-1000-2000-3000-1104"
	registered, policyReads := true, 0
	windowsMachinePolicyRegisteredSIDs = func(string, string) (map[string]bool, error) {
		policyReads++
		if !registered {
			return map[string]bool{}, nil
		}
		return map[string]bool{strings.ToUpper(sid.String()): true, peerSID: true}, nil
	}
	t.Cleanup(func() {
		windowsManagedPolicyAncestorTrustCheck, windowsManagedPolicyDirTrustCheck, windowsManagedPolicyFileTrustCheck = previousAncestor, previousDir, previousFile
		windowsManagedPolicyOwnerSID, windowsManagedRuntimeSelectorMutationAuthorize = previousOwner, previousMutation
		windowsMachinePolicyRegisteredSIDs = previousRegistered
	})
	selectorPath, err := windowsManagedRuntimeSelectorPath("claudecode")
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureWindowsManagedPolicyDirectory(filepath.Dir(selectorPath)); err != nil {
		t.Fatal(err)
	}
	publish := func(hook string) {
		t.Helper()
		var targets []windowsManagedRuntimeSelectorTarget
		for _, entrySID := range []string{sid.String(), peerSID} {
			targets = append(targets, windowsManagedRuntimeSelectorTarget{
				Connector: "claudecode", SID: entrySID, DataDir: filepath.Join(target.UserHome, ".defenseclaw"),
				HookExecutable: hook, GatewayAddr: "127.0.0.1:18970", GatewayServiceName: "DefenseClawGateway",
				GenerationID: strings.Repeat("a", 32), BundleSHA256: "sha256:" + strings.Repeat("b", 64),
			})
		}
		sort.Slice(targets, func(i, j int) bool { return targets[i].SID < targets[j].SID })
		if err := publishWindowsManagedRuntimeSelector(windowsManagedRuntimeSelector{
			SchemaVersion: windowsManagedRuntimeGenerationSchema,
			Connector:     "claudecode",
			Targets:       targets,
		}); err != nil {
			t.Fatalf("publish the selection a revocation left behind: %v", err)
		}
	}
	retireAndProve := func() error {
		t.Helper()
		if err := RetireWindowsUnregisteredRuntimeSelections(); err != nil {
			t.Fatalf("retire runtime selections: %v", err)
		}
		return RequireWindowsEnterpriseDeferredTargetPending(target)
	}
	publish(hookExe)
	if err := retireAndProve(); err == nil || !strings.Contains(err.Error(), "without protected Guardian authorization") {
		t.Fatalf("pending proof with a registered SID's selection = %v, want the refusal", err)
	}
	if policyReads != 1 {
		t.Fatalf("a pass over two registered selections read the machine policy %d times, want once", policyReads)
	}
	registered = false
	if err := retireAndProve(); err != nil {
		t.Fatalf("pending proof after the unregistered SID's selection was retired: %v", err)
	}
	if _, err := os.Lstat(selectorPath); !os.IsNotExist(err) {
		t.Fatalf("the emptied runtime selector stayed: %v", err)
	}
	publish(filepath.Join(t.TempDir(), "defenseclaw-hook.exe"))
	if err := retireAndProve(); err == nil || !strings.Contains(err.Error(), "mismatched selected runtime") {
		t.Fatalf("pending proof with another deployment's selection = %v, want the refusal", err)
	}
}
