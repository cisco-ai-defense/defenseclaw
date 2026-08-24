//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

func TestWindowsManagedRuntimeMissingChildProbeUsesValidSynchronousOpen(t *testing.T) {
	target := currentWindowsTestSID(t)
	home := newWindowsManagedRuntimeBAOwnedProfile(t, target)
	targetInfo, err := resolveWindowsManagedRuntimeTarget(home, target.String(), filepath.Join(home, ".defenseclaw"))
	if err != nil {
		t.Fatal(err)
	}
	err = windowsManagedRuntimeSetupPrivilege(func() error {
		parent, err := openWindowsManagedRuntimeProfile(targetInfo)
		if err != nil {
			return err
		}
		defer windows.CloseHandle(parent)
		return requireWindowsManagedRuntimeChildAbsent(parent, ".defenseclaw")
	})
	if err != nil {
		t.Fatalf("probe absent managed runtime child: %v", err)
	}
	if _, err := os.Lstat(targetInfo.data); !os.IsNotExist(err) {
		t.Fatalf("absence probe created or exposed a managed runtime root: %v", err)
	}
}

func TestWindowsManagedRuntimeMarkerControlContractsArePhaseExact(t *testing.T) {
	for raw := 0; raw <= 0xffff; raw++ {
		control := windows.SECURITY_DESCRIPTOR_CONTROL(raw)
		staging := windowsManagedRuntimeMarkerControlMatches(control, windowsManagedRuntimeStagingControl)
		quarantine := windowsManagedRuntimeMarkerControlMatches(control, windowsManagedRuntimeQuarantineControl)
		cleanup := windowsManagedRuntimeMarkerControlMatches(
			control,
			windowsManagedRuntimeStagingControl,
			windowsManagedRuntimeQuarantineControl,
		)
		if staging != (control == windowsManagedRuntimeStagingControl) {
			t.Fatalf("staging control contract accepted 0x%04x", raw)
		}
		if quarantine != (control == windowsManagedRuntimeQuarantineControl) {
			t.Fatalf("quarantine control contract accepted 0x%04x", raw)
		}
		wantCleanup := control == windowsManagedRuntimeStagingControl || control == windowsManagedRuntimeQuarantineControl
		if cleanup != wantCleanup {
			t.Fatalf("cleanup control contract mismatch for 0x%04x", raw)
		}
	}
}

func TestWindowsManagedRuntimeMarkerDescriptorValidatorsKeepPhaseSeparation(t *testing.T) {
	target := currentWindowsTestSID(t)
	marker, err := windows.StringToSid("S-1-5-21-101-102-103-104-105-106-107-108")
	if err != nil {
		t.Fatal(err)
	}
	staging, err := windowsManagedRuntimeStagingSecurityDescriptor(target, marker)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateWindowsManagedRuntimeMarkerDescriptor(staging, target, marker, windowsManagedRuntimeStagingControl); err != nil {
		t.Fatalf("reject exact fresh-staging descriptor: %v", err)
	}
	if err := validateWindowsManagedRuntimeMarkerDescriptor(staging, target, marker, windowsManagedRuntimeQuarantineControl); err == nil {
		t.Fatal("quarantine validator accepted fresh-staging control 0x9004")
	}

	quarantine := windowsManagedRuntimeTestDescriptorWithControl(
		t,
		staging,
		windows.SE_DACL_AUTO_INHERITED,
		windows.SE_DACL_AUTO_INHERITED,
	)
	if err := validateWindowsManagedRuntimeMarkerDescriptor(quarantine, target, marker, windowsManagedRuntimeQuarantineControl); err != nil {
		t.Fatalf("reject exact quarantine descriptor: %v", err)
	}
	if err := validateWindowsManagedRuntimeStagingDescriptor(quarantine, target, marker); err == nil {
		t.Fatal("fresh-staging validator accepted quarantine control 0x9404")
	}
	for label, descriptor := range map[string]*windows.SECURITY_DESCRIPTOR{
		"auto-inherit-request": windowsManagedRuntimeTestDescriptorWithControl(
			t,
			staging,
			windows.SE_DACL_AUTO_INHERIT_REQ,
			windows.SE_DACL_AUTO_INHERIT_REQ,
		),
		"unprotected": windowsManagedRuntimeTestDescriptorWithControl(
			t,
			staging,
			windows.SE_DACL_PROTECTED,
			0,
		),
	} {
		if err := validateWindowsManagedRuntimeMarkerDescriptor(
			descriptor,
			target,
			marker,
			windowsManagedRuntimeStagingControl,
			windowsManagedRuntimeQuarantineControl,
		); err == nil {
			t.Fatalf("cleanup validator accepted %s descriptor", label)
		}
	}
}

func windowsManagedRuntimeTestDescriptorWithControl(
	t *testing.T,
	descriptor *windows.SECURITY_DESCRIPTOR,
	bitsOfInterest, bitsToSet windows.SECURITY_DESCRIPTOR_CONTROL,
) *windows.SECURITY_DESCRIPTOR {
	t.Helper()
	absolute, err := descriptor.ToAbsolute()
	if err != nil {
		t.Fatal(err)
	}
	if err := absolute.SetControl(bitsOfInterest, bitsToSet); err != nil {
		t.Fatal(err)
	}
	selfRelative, err := absolute.ToSelfRelative()
	if err != nil {
		t.Fatal(err)
	}
	return selfRelative
}

func TestWindowsManagedRuntimeStagesJournalsAndPublishesExactTargetRoot(t *testing.T) {
	target := currentWindowsTestSID(t)
	home := newWindowsManagedRuntimeBAOwnedProfile(t, target)
	manifest := windowsManagedRuntimeTestManifest(home, target)
	digest := strings.Repeat("a", 64)
	plan, err := PlanWindowsManagedRuntimeRoots(manifest, `C:\ProgramData\DefenseClaw\etc\targets.yaml`, digest)
	if err != nil {
		t.Fatalf("plan managed runtime roots: %v", err)
	}
	if len(plan.Roots) != 1 || plan.Roots[0].Baseline != windowsManagedRuntimeBaselineAbsent {
		t.Fatalf("plan roots = %+v, want one absent de-duplicated root", plan.Roots)
	}
	if plan.TargetCount != 3 {
		t.Fatalf("plan target count = %d, want all three enabled connector rows", plan.TargetCount)
	}
	if _, err := os.Lstat(filepath.Join(home, ".defenseclaw")); !os.IsNotExist(err) {
		t.Fatalf("non-mutating plan published final root: %v", err)
	}

	journalCalls := 0
	claims, err := StageWindowsManagedRuntimeRoots(plan, manifest, digest, func(got []WindowsManagedRuntimeClaim) error {
		journalCalls++
		if len(got) != 1 || got[0].Identity == "" || !got[0].Created || got[0].State != windowsManagedRuntimeStateStaged {
			t.Fatalf("stage journal = %+v", got)
		}
		stagePath := filepath.Join(home, plan.Roots[0].StagingLeaf)
		stage, openErr := openWindowsTestDirectoryNoFollow(stagePath)
		if openErr != nil {
			t.Fatalf("journal callback cannot bind live staging root: %v", openErr)
		}
		_ = windows.CloseHandle(stage)
		if _, statErr := os.Lstat(filepath.Join(home, ".defenseclaw")); !os.IsNotExist(statErr) {
			t.Fatalf("stage journal observed prematurely published final root: %v", statErr)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("stage managed runtime root: %v", err)
	}
	if journalCalls != 1 || len(claims) != 1 {
		t.Fatalf("stage journal calls=%d claims=%+v", journalCalls, claims)
	}

	request := WindowsManagedRuntimeRequest{SchemaVersion: WindowsManagedRuntimeRequestSchemaVersion, Plan: plan, Claims: claims}
	finalClaims, err := FinalizeWindowsManagedRuntimeRoots(request, manifest, digest)
	if err != nil {
		t.Fatalf("finalize managed runtime root: %v", err)
	}
	if len(finalClaims) != 1 || finalClaims[0].Identity != claims[0].Identity || finalClaims[0].State != windowsManagedRuntimeStateCanonical {
		t.Fatalf("final claims = %+v, want same canonical inode", finalClaims)
	}
	dataDir := filepath.Join(home, ".defenseclaw")
	assertWindowsTargetOwnedCanonicalDirectory(t, dataDir, target)
	if _, err := os.Lstat(filepath.Join(home, plan.Roots[0].StagingLeaf)); !os.IsNotExist(err) {
		t.Fatalf("staging name survived finalization: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "inventory.db"), []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Simulate a process death after final owner/DACL publication but before the
	// final report was journaled: the durable stage claims still authenticate
	// the same canonical inode for cleanup.
	cleanupRequest := WindowsManagedRuntimeRequest{SchemaVersion: WindowsManagedRuntimeRequestSchemaVersion, Plan: plan, Claims: claims}
	cleanupClaims, err := CleanupWindowsManagedRuntimeRoots(cleanupRequest, manifest, digest)
	if err != nil {
		t.Fatalf("cleanup managed runtime root: %v", err)
	}
	if len(cleanupClaims) != 1 || cleanupClaims[0].State != windowsManagedRuntimeStateAbsent {
		t.Fatalf("cleanup claims = %+v", cleanupClaims)
	}
	if _, err := os.Lstat(dataDir); !os.IsNotExist(err) {
		t.Fatalf("created managed runtime root survived rollback cleanup: %v", err)
	}
}

func TestWindowsManagedRuntimePublishesForeignTargetWithRestorePrivilege(t *testing.T) {
	processTarget := currentWindowsTestSID(t)
	foreignTarget, err := windows.StringToSid("S-1-5-21-1947302811-2864019257-3719054423-1001")
	if err != nil {
		t.Fatal(err)
	}
	if foreignTarget.Equals(processTarget) {
		t.Fatal("foreign target fixture unexpectedly equals the process user")
	}
	home := newWindowsManagedRuntimeForeignBAOwnedProfile(t, foreignTarget)
	manifest := windowsManagedRuntimeTestManifest(home, foreignTarget)
	digest := strings.Repeat("9", 64)
	plan, err := PlanWindowsManagedRuntimeRoots(manifest, `C:\ProgramData\DefenseClaw\etc\targets.yaml`, digest)
	if err != nil {
		t.Fatalf("plan foreign target: %v", err)
	}
	claims, err := StageWindowsManagedRuntimeRoots(plan, manifest, digest, func([]WindowsManagedRuntimeClaim) error { return nil })
	if err != nil {
		t.Fatalf("stage marker-owned foreign target: %v", err)
	}
	request := WindowsManagedRuntimeRequest{SchemaVersion: WindowsManagedRuntimeRequestSchemaVersion, Plan: plan, Claims: claims}
	final, err := FinalizeWindowsManagedRuntimeRoots(request, manifest, digest)
	if err != nil {
		t.Fatalf("publish foreign target owner with SeRestorePrivilege: %v", err)
	}
	if len(final) != 1 || final[0].Identity != claims[0].Identity || !final[0].Created {
		t.Fatalf("foreign target final claims = %+v", final)
	}
	assertWindowsTargetOwnedCanonicalDirectory(t, filepath.Join(home, ".defenseclaw"), foreignTarget)

	// runWindowsManagedRuntimeSetupPrivilege verifies ERROR_NO_TOKEN on its
	// dedicated thread before returning it to the runtime. Reaching this cleanup
	// proves both the foreign-owner operation and the post-operation reversion.
	if _, err := CleanupWindowsManagedRuntimeRoots(
		WindowsManagedRuntimeRequest{SchemaVersion: WindowsManagedRuntimeRequestSchemaVersion, Plan: plan, Claims: final},
		manifest,
		digest,
	); err != nil {
		t.Fatalf("cleanup foreign target fixture: %v", err)
	}
}

func TestWindowsManagedRuntimeFinalizeRecoversMarkerOwnerAfterHandleRename(t *testing.T) {
	target := currentWindowsTestSID(t)
	home := newWindowsTargetOwnedTestHome(t, target)
	manifest := windowsManagedRuntimeTestManifest(home, target)
	digest := strings.Repeat("d", 64)
	plan, err := PlanWindowsManagedRuntimeRoots(manifest, `C:\ProgramData\DefenseClaw\etc\targets.yaml`, digest)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := StageWindowsManagedRuntimeRoots(plan, manifest, digest, func([]WindowsManagedRuntimeClaim) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	rootPlan := plan.Roots[0]
	targetInfo, err := resolveWindowsManagedRuntimeTarget(rootPlan.UserHome, rootPlan.SID, rootPlan.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	err = windowsManagedRuntimeSetupPrivilege(func() error {
		parent, err := openWindowsManagedRuntimeProfile(targetInfo)
		if err != nil {
			return err
		}
		defer windows.CloseHandle(parent)
		stage, err := openWindowsManagedRuntimeChild(parent, rootPlan.StagingLeaf, windowsManagedRuntimeStageMutationAccess(), false)
		if err != nil {
			return err
		}
		defer windows.CloseHandle(stage)
		marker, err := windows.StringToSid(rootPlan.MarkerSID)
		if err != nil {
			return err
		}
		if err := validateWindowsManagedRuntimeStagingHandle(stage, target, marker); err != nil {
			return err
		}
		return renameWindowsManagedRuntimeHandle(stage, parent, ".defenseclaw")
	})
	if err != nil {
		t.Fatalf("simulate crash after marker-owner rename: %v", err)
	}
	marker, _ := windows.StringToSid(rootPlan.MarkerSID)
	owner, err := windowsPathOwnerNoFollow(filepath.Join(home, ".defenseclaw"))
	if err != nil || owner == nil || !owner.Equals(marker) {
		t.Fatalf("crash-window final owner=%v err=%v, want marker %s", owner, err, marker)
	}
	withWindowsManagedRuntimeRestrictedTarget(t, func() {
		attackerChild := filepath.Join(home, ".defenseclaw", "attacker-child")
		if writeErr := os.WriteFile(attackerChild, []byte("blocked"), 0o600); writeErr == nil {
			t.Fatal("restricted target wrote into marker-owned final name before canonicalization")
		}
	})
	request := WindowsManagedRuntimeRequest{SchemaVersion: WindowsManagedRuntimeRequestSchemaVersion, Plan: plan, Claims: claims}
	final, err := FinalizeWindowsManagedRuntimeRoots(request, manifest, digest)
	if err != nil {
		t.Fatalf("recover marker-owner final root: %v", err)
	}
	if len(final) != 1 || final[0].Identity != claims[0].Identity {
		t.Fatalf("recovered final claims=%+v", final)
	}
	assertWindowsTargetOwnedCanonicalDirectory(t, filepath.Join(home, ".defenseclaw"), target)
	if _, err := CleanupWindowsManagedRuntimeRoots(
		WindowsManagedRuntimeRequest{SchemaVersion: WindowsManagedRuntimeRequestSchemaVersion, Plan: plan, Claims: final},
		manifest,
		digest,
	); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsManagedRuntimeFinalizeNeverReplacesCollision(t *testing.T) {
	target := currentWindowsTestSID(t)
	home := newWindowsTargetOwnedTestHome(t, target)
	manifest := windowsManagedRuntimeTestManifest(home, target)
	digest := strings.Repeat("e", 64)
	plan, err := PlanWindowsManagedRuntimeRoots(manifest, `C:\ProgramData\DefenseClaw\etc\targets.yaml`, digest)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := StageWindowsManagedRuntimeRoots(plan, manifest, digest, func([]WindowsManagedRuntimeClaim) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	collision := filepath.Join(home, ".defenseclaw")
	if err := os.Mkdir(collision, 0o700); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(collision)
	if err != nil {
		t.Fatal(err)
	}
	request := WindowsManagedRuntimeRequest{SchemaVersion: WindowsManagedRuntimeRequestSchemaVersion, Plan: plan, Claims: claims}
	if _, err := FinalizeWindowsManagedRuntimeRoots(request, manifest, digest); err == nil {
		t.Fatal("finalize replaced a competing final directory")
	}
	after, err := os.Stat(collision)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("collision identity changed: %v", err)
	}
	if err := os.Remove(collision); err != nil {
		t.Fatal(err)
	}
	if _, err := CleanupWindowsManagedRuntimeRoots(request, manifest, digest); err != nil {
		t.Fatalf("cleanup collision staging root: %v", err)
	}
}

func TestWindowsManagedRuntimeCleanupRejectsUnexpectedContent(t *testing.T) {
	target := currentWindowsTestSID(t)
	home := newWindowsTargetOwnedTestHome(t, target)
	manifest := windowsManagedRuntimeTestManifest(home, target)
	digest := strings.Repeat("f", 64)
	plan, err := PlanWindowsManagedRuntimeRoots(manifest, `C:\ProgramData\DefenseClaw\etc\targets.yaml`, digest)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := StageWindowsManagedRuntimeRoots(plan, manifest, digest, func([]WindowsManagedRuntimeClaim) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	request := WindowsManagedRuntimeRequest{SchemaVersion: WindowsManagedRuntimeRequestSchemaVersion, Plan: plan, Claims: claims}
	if _, err := FinalizeWindowsManagedRuntimeRoots(request, manifest, digest); err != nil {
		t.Fatal(err)
	}
	unexpected := filepath.Join(home, ".defenseclaw", "user-owned.txt")
	if err := os.WriteFile(unexpected, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := CleanupWindowsManagedRuntimeRoots(request, manifest, digest); err == nil {
		t.Fatal("cleanup deleted or accepted unexpected target content")
	}
	if data, err := os.ReadFile(unexpected); err != nil || string(data) != "preserve" {
		t.Fatalf("unexpected target content changed: data=%q err=%v", data, err)
	}
	if err := os.Remove(unexpected); err != nil {
		t.Fatal(err)
	}
	if _, err := CleanupWindowsManagedRuntimeRoots(request, manifest, digest); err != nil {
		t.Fatalf("cleanup after removing unexpected content: %v", err)
	}
}

func TestWindowsManagedRuntimeCleanupValidatesCanonicalBaselineWithoutDeletingIt(t *testing.T) {
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
	if len(plan.Roots) != 1 || plan.Roots[0].Baseline != windowsManagedRuntimeBaselineCanonical {
		t.Fatalf("plan roots = %+v, want canonical baseline", plan.Roots)
	}
	request := WindowsManagedRuntimeRequest{SchemaVersion: WindowsManagedRuntimeRequestSchemaVersion, Plan: plan}
	claims, err := CleanupWindowsManagedRuntimeRoots(request, manifest, digest)
	if err != nil {
		t.Fatalf("validate unchanged canonical baseline: %v", err)
	}
	if len(claims) != 1 || claims[0].Identity != plan.Roots[0].BaselineIdentity || claims[0].Created || claims[0].State != windowsManagedRuntimeStateCanonical {
		t.Fatalf("canonical cleanup claims = %+v", claims)
	}
	assertWindowsTargetOwnedCanonicalDirectory(t, dataDir, target)

	preserved := filepath.Join(home, "preserved-canonical-root")
	if err := os.Rename(dataDir, preserved); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureWindowsTargetOwnedDirectoryTree(home, hookDir, target); err != nil {
		t.Fatal(err)
	}
	if _, err := CleanupWindowsManagedRuntimeRoots(request, manifest, digest); err == nil {
		t.Fatal("cleanup accepted a replacement for the canonical baseline identity")
	}
	assertWindowsTargetOwnedCanonicalDirectory(t, dataDir, target)
	assertWindowsTargetOwnedCanonicalDirectory(t, preserved, target)
}

func TestWindowsManagedRuntimeCleanupRejectsCanonicalBaselineDACLDrift(t *testing.T) {
	target := currentWindowsTestSID(t)
	home := newWindowsTargetOwnedTestHome(t, target)
	dataDir := filepath.Join(home, ".defenseclaw")
	hookDir := filepath.Join(dataDir, "hooks")
	if _, err := ensureWindowsTargetOwnedDirectoryTree(home, hookDir, target); err != nil {
		t.Fatal(err)
	}
	manifest := windowsManagedRuntimeTestManifest(home, target)
	digest := strings.Repeat("3", 64)
	plan, err := PlanWindowsManagedRuntimeRoots(manifest, `C:\ProgramData\DefenseClaw\etc\targets.yaml`, digest)
	if err != nil {
		t.Fatal(err)
	}
	drifted, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		windowsManagedRuntimeTestAccess(target, 0x001f01ff),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		dataDir,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		drifted,
		nil,
	); err != nil {
		t.Fatal(err)
	}
	request := WindowsManagedRuntimeRequest{SchemaVersion: WindowsManagedRuntimeRequestSchemaVersion, Plan: plan}
	if _, err := CleanupWindowsManagedRuntimeRoots(request, manifest, digest); err == nil {
		t.Fatal("cleanup reported success for a drifted canonical baseline DACL")
	}
	if _, err := os.Lstat(dataDir); err != nil {
		t.Fatalf("cleanup deleted drifted canonical baseline: %v", err)
	}
}

func TestWindowsManagedRuntimeCleanupReportsPartialMultiRootFailureConservatively(t *testing.T) {
	currentTarget := currentWindowsTestSID(t)
	foreignTarget, err := windows.StringToSid("S-1-5-21-1947302811-2864019257-3719054423-1002")
	if err != nil {
		t.Fatal(err)
	}
	currentHome := newWindowsManagedRuntimeBAOwnedProfile(t, currentTarget)
	foreignHome := newWindowsManagedRuntimeForeignBAOwnedProfile(t, foreignTarget)
	manifest := Manifest{Version: 1, Targets: []ManifestTarget{
		{UserHome: currentHome, SID: currentTarget.String(), DataDir: filepath.Join(currentHome, ".defenseclaw"), Connector: "codex", AgentVersion: "0.1.0"},
		{UserHome: foreignHome, SID: foreignTarget.String(), DataDir: filepath.Join(foreignHome, ".defenseclaw"), Connector: "cursor", AgentVersion: "1.0.0"},
	}}
	digest := strings.Repeat("8", 64)
	plan, err := PlanWindowsManagedRuntimeRoots(manifest, `C:\ProgramData\DefenseClaw\etc\targets.yaml`, digest)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Roots) != 2 {
		t.Fatalf("plan roots = %+v", plan.Roots)
	}
	staged, err := StageWindowsManagedRuntimeRoots(plan, manifest, digest, func([]WindowsManagedRuntimeClaim) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	request := WindowsManagedRuntimeRequest{SchemaVersion: WindowsManagedRuntimeRequestSchemaVersion, Plan: plan, Claims: staged}
	final, err := FinalizeWindowsManagedRuntimeRoots(request, manifest, digest)
	if err != nil {
		t.Fatal(err)
	}
	request.Claims = final
	unexpected := filepath.Join(plan.Roots[1].DataDir, "preserve-me.txt")
	if err := os.WriteFile(unexpected, []byte("user evidence"), 0o600); err != nil {
		t.Fatal(err)
	}

	partial, err := CleanupWindowsManagedRuntimeRoots(request, manifest, digest)
	if err == nil {
		t.Fatal("multi-root cleanup accepted unexpected content")
	}
	if len(partial) != 2 || partial[0].State != windowsManagedRuntimeStateAbsent {
		t.Fatalf("partial cleanup report = %+v, want first root verified absent", partial)
	}
	if partial[1].State != windowsManagedRuntimeStateCanonical || partial[1].Identity != final[1].Identity || !partial[1].Created {
		t.Fatalf("failed root was falsely reported absent: got %+v want canonical identity %s", partial[1], final[1].Identity)
	}
	if data, readErr := os.ReadFile(unexpected); readErr != nil || string(data) != "user evidence" {
		t.Fatalf("unexpected content changed: data=%q err=%v", data, readErr)
	}
	if _, statErr := os.Lstat(plan.Roots[0].DataDir); !os.IsNotExist(statErr) {
		t.Fatalf("first root was not removed before second-root failure: %v", statErr)
	}
	if err := os.Remove(unexpected); err != nil {
		t.Fatal(err)
	}
	if _, err := CleanupWindowsManagedRuntimeRoots(request, manifest, digest); err != nil {
		t.Fatalf("finish multi-root cleanup after preserving evidence: %v", err)
	}
}

func TestWindowsManagedRuntimeCleanupRemovesExactMultiConnectorFreshFootprint(t *testing.T) {
	target := currentWindowsTestSID(t)
	home := newWindowsManagedRuntimeBAOwnedProfile(t, target)
	manifest := windowsManagedRuntimeTestManifest(home, target)
	digest := strings.Repeat("7", 64)
	plan, err := PlanWindowsManagedRuntimeRoots(manifest, `C:\ProgramData\DefenseClaw\etc\targets.yaml`, digest)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := StageWindowsManagedRuntimeRoots(plan, manifest, digest, func([]WindowsManagedRuntimeClaim) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	request := WindowsManagedRuntimeRequest{SchemaVersion: WindowsManagedRuntimeRequestSchemaVersion, Plan: plan, Claims: staged}
	final, err := FinalizeWindowsManagedRuntimeRoots(request, manifest, digest)
	if err != nil {
		t.Fatal(err)
	}
	request.Claims = final
	specs, err := windowsManagedRuntimeCleanupSpecs(plan, manifest)
	if err != nil {
		t.Fatal(err)
	}
	spec := specs[windowsManagedRuntimeRootKey(plan.Roots[0].SID, plan.Roots[0].UserHome)]
	known := writeWindowsManagedRuntimeCleanupFixture(t, plan.Roots[0], target, spec)
	for index, connectorName := range []string{"codex", "claudecode", "cursor"} {
		leaf, err := windowsManagedRuntimeBundleLeaf(
			connectorName,
			fmt.Sprintf("%032x", index+1),
		)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(plan.Roots[0].DataDir, "hooks", leaf)
		if err := os.WriteFile(path, []byte("immutable managed runtime generation"), 0o600); err != nil {
			t.Fatal(err)
		}
		setWindowsManagedRuntimeCleanupFileCanonical(t, path, target)
		known = append(known, path)
	}

	// An unknown nested file must reject the entire tree before even one exact
	// root/lock/token/script artifact is deleted.
	unexpected := filepath.Join(plan.Roots[0].DataDir, "hooks", "user-evidence.txt")
	if err := os.WriteFile(unexpected, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := CleanupWindowsManagedRuntimeRoots(request, manifest, digest); err == nil {
		t.Fatal("cleanup accepted an unknown post-reconcile hook file")
	}
	for _, path := range known {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("full-tree preflight deleted %s before rejecting unknown content: %v", path, err)
		}
	}
	if data, err := os.ReadFile(unexpected); err != nil || string(data) != "preserve" {
		t.Fatalf("unknown nested evidence changed: data=%q err=%v", data, err)
	}
	if err := os.Remove(unexpected); err != nil {
		t.Fatal(err)
	}
	if _, err := CleanupWindowsManagedRuntimeRoots(request, manifest, digest); err != nil {
		t.Fatalf("cleanup exact multi-connector fresh footprint: %v", err)
	}
	if _, err := os.Lstat(plan.Roots[0].DataDir); !os.IsNotExist(err) {
		t.Fatalf("exact fresh footprint survived cleanup: %v", err)
	}
}

func TestWindowsManagedRuntimeCleanupRefusesPinnedWriterBeforeMutation(t *testing.T) {
	target := currentWindowsTestSID(t)
	home := newWindowsManagedRuntimeBAOwnedProfile(t, target)
	manifest := windowsManagedRuntimeTestManifest(home, target)
	digest := strings.Repeat("6", 64)
	plan, err := PlanWindowsManagedRuntimeRoots(manifest, `C:\ProgramData\DefenseClaw\etc\targets.yaml`, digest)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := StageWindowsManagedRuntimeRoots(plan, manifest, digest, func([]WindowsManagedRuntimeClaim) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	request := WindowsManagedRuntimeRequest{SchemaVersion: WindowsManagedRuntimeRequestSchemaVersion, Plan: plan, Claims: staged}
	final, err := FinalizeWindowsManagedRuntimeRoots(request, manifest, digest)
	if err != nil {
		t.Fatal(err)
	}
	request.Claims = final
	specs, err := windowsManagedRuntimeCleanupSpecs(plan, manifest)
	if err != nil {
		t.Fatal(err)
	}
	spec := specs[windowsManagedRuntimeRootKey(plan.Roots[0].SID, plan.Roots[0].UserHome)]
	known := writeWindowsManagedRuntimeCleanupFixture(t, plan.Roots[0], target, spec)
	extendedRoot, err := winpath.Extended(plan.Roots[0].DataDir)
	if err != nil {
		t.Fatal(err)
	}
	rootPtr, err := windows.UTF16PtrFromString(extendedRoot)
	if err != nil {
		t.Fatal(err)
	}
	rootWriter, err := windows.CreateFile(
		rootPtr,
		windows.FILE_WRITE_DATA|windows.FILE_APPEND_DATA|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		t.Fatalf("open live root add-file handle: %v", err)
	}
	if _, err := CleanupWindowsManagedRuntimeRoots(request, manifest, digest); err == nil {
		_ = windows.CloseHandle(rootWriter)
		t.Fatal("cleanup proceeded while the runtime root had a live add-file handle")
	}
	for _, path := range known {
		if _, err := os.Lstat(path); err != nil {
			_ = windows.CloseHandle(rootWriter)
			t.Fatalf("root-writer sharing refusal partially deleted %s: %v", path, err)
		}
	}
	if err := windows.CloseHandle(rootWriter); err != nil {
		t.Fatal(err)
	}

	writePath := filepath.Join(plan.Roots[0].DataDir, "hooks", ".hookcfg")
	writer, err := os.OpenFile(writePath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CleanupWindowsManagedRuntimeRoots(request, manifest, digest); err == nil {
		_ = writer.Close()
		t.Fatal("cleanup proceeded while a managed artifact had a live writer")
	}
	for _, path := range known {
		if _, err := os.Lstat(path); err != nil {
			_ = writer.Close()
			t.Fatalf("writer-sharing refusal partially deleted %s: %v", path, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := CleanupWindowsManagedRuntimeRoots(request, manifest, digest); err != nil {
		t.Fatalf("cleanup after writer release: %v", err)
	}
}

func TestWindowsManagedRuntimeCleanupQuarantineBlocksPostPreflightPathMutation(t *testing.T) {
	target := currentWindowsTestSID(t)
	if target.IsWellKnown(windows.WinLocalSystemSid) {
		t.Skip("LocalSystem remains trusted by the quarantine DACL")
	}
	home := newWindowsManagedRuntimeBAOwnedProfile(t, target)
	manifest := windowsManagedRuntimeTestManifest(home, target)
	digest := strings.Repeat("2", 64)
	plan, err := PlanWindowsManagedRuntimeRoots(manifest, `C:\ProgramData\DefenseClaw\etc\targets.yaml`, digest)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := StageWindowsManagedRuntimeRoots(plan, manifest, digest, func([]WindowsManagedRuntimeClaim) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	request := WindowsManagedRuntimeRequest{SchemaVersion: WindowsManagedRuntimeRequestSchemaVersion, Plan: plan, Claims: staged}
	final, err := FinalizeWindowsManagedRuntimeRoots(request, manifest, digest)
	if err != nil {
		t.Fatal(err)
	}
	request.Claims = final
	specs, err := windowsManagedRuntimeCleanupSpecs(plan, manifest)
	if err != nil {
		t.Fatal(err)
	}
	spec := specs[windowsManagedRuntimeRootKey(plan.Roots[0].SID, plan.Roots[0].UserHome)]
	known := writeWindowsManagedRuntimeCleanupFixture(t, plan.Roots[0], target, spec)

	restricted, err := createWindowsManagedRuntimeRestrictedToken()
	if err != nil {
		if errors.Is(err, windows.ERROR_PROC_NOT_FOUND) || errors.Is(err, windows.ERROR_CALL_NOT_IMPLEMENTED) || errors.Is(err, windows.ERROR_NOT_SUPPORTED) {
			t.Skipf("CreateRestrictedToken unavailable: %v", err)
		}
		t.Fatal(err)
	}
	defer restricted.Close() //nolint:errcheck
	called := false
	injected := errors.New("inject stop after managed runtime quarantine")
	windowsManagedRuntimeCleanupPostPreflight = func(rootPath, hookPath string) error {
		called = true
		return runWindowsManagedRuntimeRestrictedToken(restricted, func() error {
			if err := requireWindowsManagedRuntimeAdministratorsDisabled(); err != nil {
				return err
			}
			createErr := os.WriteFile(filepath.Join(rootPath, "post-preflight-new"), []byte("blocked"), 0o600)
			if createErr == nil {
				return errors.New("restricted target created a child after cleanup preflight")
			}
			if !windowsManagedRuntimePathMutationDenied(createErr) {
				return fmt.Errorf("post-preflight child create returned %w, want access or sharing denial", createErr)
			}
			renameErr := os.Rename(filepath.Join(hookPath, ".hookcfg"), filepath.Join(rootPath, "post-preflight-renamed"))
			if renameErr == nil {
				return errors.New("restricted target renamed a pinned child after cleanup preflight")
			}
			if !windowsManagedRuntimePathMutationDenied(renameErr) {
				return fmt.Errorf("post-preflight child rename returned %w, want access or sharing denial", renameErr)
			}
			return injected
		})
	}
	defer func() { windowsManagedRuntimeCleanupPostPreflight = nil }()
	partial, err := CleanupWindowsManagedRuntimeRoots(request, manifest, digest)
	if !errors.Is(err, injected) {
		t.Fatalf("cleanup quarantine synchronization result = %v, want injected stop after denied mutations", err)
	}
	if len(partial) != 1 || partial[0].State != windowsManagedRuntimeStateStaged ||
		partial[0].Identity != final[0].Identity || !partial[0].Created {
		t.Fatalf("failed quarantined cleanup report = %+v, want authenticated staged identity %s", partial, final[0].Identity)
	}
	if !called {
		t.Fatal("cleanup did not reach synchronized post-preflight seam")
	}
	for _, path := range known {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("injected quarantine stop partially deleted %s: %v", path, err)
		}
	}
	marker, err := windows.StringToSid(plan.Roots[0].MarkerSID)
	if err != nil {
		t.Fatal(err)
	}
	quarantined, err := openWindowsTestDirectoryNoFollow(plan.Roots[0].DataDir)
	if err != nil {
		t.Fatalf("reopen quarantined root after injected stop: %v", err)
	}
	if err := validateWindowsManagedRuntimeQuarantineHandle(quarantined, target, marker); err != nil {
		_ = windows.CloseHandle(quarantined)
		t.Fatalf("injected stop did not preserve authenticated marker quarantine: %v", err)
	}
	if err := windows.CloseHandle(quarantined); err != nil {
		t.Fatal(err)
	}
	windowsManagedRuntimeCleanupPostPreflight = nil
	if _, err := CleanupWindowsManagedRuntimeRoots(request, manifest, digest); err != nil {
		t.Fatalf("cleanup did not recover marker-quarantined exact footprint: %v", err)
	}
	if _, err := os.Lstat(plan.Roots[0].DataDir); !os.IsNotExist(err) {
		t.Fatalf("quarantined exact footprint survived cleanup: %v", err)
	}
}

func TestWindowsManagedRuntimeFailedCleanupOmitsUnverifiedLiveState(t *testing.T) {
	target := currentWindowsTestSID(t)
	home := newWindowsManagedRuntimeBAOwnedProfile(t, target)
	manifest := windowsManagedRuntimeTestManifest(home, target)
	digest := strings.Repeat("b", 64)
	plan, err := PlanWindowsManagedRuntimeRoots(manifest, `C:\ProgramData\DefenseClaw\etc\targets.yaml`, digest)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := StageWindowsManagedRuntimeRoots(plan, manifest, digest, func([]WindowsManagedRuntimeClaim) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	request := WindowsManagedRuntimeRequest{SchemaVersion: WindowsManagedRuntimeRequestSchemaVersion, Plan: plan, Claims: staged}
	final, err := FinalizeWindowsManagedRuntimeRoots(request, manifest, digest)
	if err != nil {
		t.Fatal(err)
	}
	request.Claims = final
	specs, err := windowsManagedRuntimeCleanupSpecs(plan, manifest)
	if err != nil {
		t.Fatal(err)
	}
	spec := specs[windowsManagedRuntimeRootKey(plan.Roots[0].SID, plan.Roots[0].UserHome)]
	known := writeWindowsManagedRuntimeCleanupFixture(t, plan.Roots[0], target, spec)
	marker, err := windows.StringToSid(plan.Roots[0].MarkerSID)
	if err != nil {
		t.Fatal(err)
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	noncanonical, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		windowsManagedRuntimeTestAccess(administrators, 0x001f01ff),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	called := false
	injected := errors.New("inject stop after installing unverified managed runtime DACL")
	windowsManagedRuntimeCleanupPostPreflight = func(rootPath, _ string) error {
		called = true
		handle, err := openWindowsTestDirectoryNoFollowAccess(
			rootPath,
			windows.WRITE_DAC|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES,
		)
		if err != nil {
			return fmt.Errorf("open quarantined root for trusted test mutation: %w", err)
		}
		defer windows.CloseHandle(handle)
		if err := windows.SetSecurityInfo(
			handle,
			windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
			nil,
			nil,
			noncanonical,
			nil,
		); err != nil {
			return fmt.Errorf("install deliberately noncanonical protected DACL: %w", err)
		}
		runtime.KeepAlive(noncanonical)
		return injected
	}
	defer func() { windowsManagedRuntimeCleanupPostPreflight = nil }()
	partial, err := CleanupWindowsManagedRuntimeRoots(request, manifest, digest)
	if !errors.Is(err, injected) {
		t.Fatalf("cleanup result = %v, want injected failure after DACL mutation", err)
	}
	if !called {
		t.Fatal("cleanup did not reach synchronized post-preflight seam")
	}
	if len(partial) != 0 {
		t.Fatalf("failed cleanup reported unauthenticated live state: %+v", partial)
	}
	for _, path := range known {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("unverified failed cleanup removed evidence %s: %v", path, err)
		}
	}

	unverified, err := openWindowsTestDirectoryNoFollow(plan.Roots[0].DataDir)
	if err != nil {
		t.Fatalf("reopen unverified managed runtime root: %v", err)
	}
	if err := validateWindowsManagedRuntimeCleanupMarkerHandle(unverified, target, marker); err == nil {
		_ = windows.CloseHandle(unverified)
		t.Fatal("deliberately noncanonical DACL passed cleanup marker validation")
	}
	if err := validateWindowsTargetOwnedDirectoryHandle(unverified, plan.Roots[0].DataDir, target); err == nil {
		_ = windows.CloseHandle(unverified)
		t.Fatal("marker-owned root with deliberately noncanonical DACL passed canonical validation")
	}
	if err := windows.CloseHandle(unverified); err != nil {
		t.Fatal(err)
	}

	if err := windowsManagedRuntimeSetupPrivilege(func() error {
		handle, err := openWindowsTestDirectoryNoFollowAccess(
			plan.Roots[0].DataDir,
			windowsManagedRuntimeCleanupRootAccess(),
		)
		if err != nil {
			return err
		}
		defer windows.CloseHandle(handle)
		return setWindowsManagedRuntimeMarkerSecurity(handle, target, marker)
	}); err != nil {
		t.Fatalf("restore exact managed runtime quarantine descriptor: %v", err)
	}
	windowsManagedRuntimeCleanupPostPreflight = nil
	if _, err := CleanupWindowsManagedRuntimeRoots(request, manifest, digest); err != nil {
		t.Fatalf("cleanup after restoring authenticated quarantine: %v", err)
	}
	if _, err := os.Lstat(plan.Roots[0].DataDir); !os.IsNotExist(err) {
		t.Fatalf("restored quarantined root survived cleanup: %v", err)
	}
}

func TestWindowsManagedRuntimeCleanupRejectsHardlinkedReservedFile(t *testing.T) {
	target := currentWindowsTestSID(t)
	home := newWindowsManagedRuntimeBAOwnedProfile(t, target)
	manifest := windowsManagedRuntimeTestManifest(home, target)
	digest := strings.Repeat("5", 64)
	plan, err := PlanWindowsManagedRuntimeRoots(manifest, `C:\ProgramData\DefenseClaw\etc\targets.yaml`, digest)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := StageWindowsManagedRuntimeRoots(plan, manifest, digest, func([]WindowsManagedRuntimeClaim) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	request := WindowsManagedRuntimeRequest{SchemaVersion: WindowsManagedRuntimeRequestSchemaVersion, Plan: plan, Claims: staged}
	final, err := FinalizeWindowsManagedRuntimeRoots(request, manifest, digest)
	if err != nil {
		t.Fatal(err)
	}
	request.Claims = final
	outside := filepath.Join(filepath.Dir(home), "outside-inventory")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(plan.Roots[0].DataDir, "inventory.db")
	if err := os.Link(outside, linked); err != nil {
		t.Fatal(err)
	}
	if _, err := CleanupWindowsManagedRuntimeRoots(request, manifest, digest); err == nil {
		t.Fatal("cleanup accepted a hardlinked reserved inventory name")
	}
	if data, err := os.ReadFile(outside); err != nil || string(data) != "outside" {
		t.Fatalf("outside hardlink target changed: data=%q err=%v", data, err)
	}
	if _, err := os.Lstat(linked); err != nil {
		t.Fatalf("hardlinked evidence was deleted: %v", err)
	}
	if err := os.Remove(linked); err != nil {
		t.Fatal(err)
	}
	if _, err := CleanupWindowsManagedRuntimeRoots(request, manifest, digest); err != nil {
		t.Fatalf("cleanup after hardlink evidence removal: %v", err)
	}
}

func TestWindowsManagedRuntimeMarkerStageDeniesRestrictedTargetSecurityAccess(t *testing.T) {
	processUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || processUser == nil || processUser.User.Sid == nil {
		t.Fatalf("resolve process user: %v", err)
	}
	target := processUser.User.Sid
	if target.IsWellKnown(windows.WinLocalSystemSid) {
		t.Skip("LocalSystem cannot isolate the Administrators/System staging grants")
	}
	home := newWindowsManagedRuntimeBAOwnedProfile(t, target)
	manifest := windowsManagedRuntimeTestManifest(home, target)
	digest := strings.Repeat("b", 64)
	plan, err := PlanWindowsManagedRuntimeRoots(manifest, `C:\ProgramData\DefenseClaw\etc\targets.yaml`, digest)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := StageWindowsManagedRuntimeRoots(plan, manifest, digest, func([]WindowsManagedRuntimeClaim) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(claims) != 1 {
		t.Fatalf("claims = %+v", claims)
	}
	stagePath := filepath.Join(home, plan.Roots[0].StagingLeaf)
	marker, err := windows.StringToSid(plan.Roots[0].MarkerSID)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := windowsPathOwnerNoFollow(stagePath)
	if err != nil || owner == nil || !owner.Equals(marker) {
		t.Fatalf("staging owner=%v err=%v, want exact random marker %s", owner, err, marker)
	}
	forgedLeaf := windowsManagedRuntimeStagePrefix + strings.Repeat("f", windowsManagedRuntimeStageRandomBytes*2)
	if forgedLeaf == plan.Roots[0].StagingLeaf {
		forgedLeaf = windowsManagedRuntimeStagePrefix + strings.Repeat("e", windowsManagedRuntimeStageRandomBytes*2)
	}
	forgedPath := filepath.Join(home, forgedLeaf)
	forgedDescriptor, err := windowsManagedRuntimeStagingSecurityDescriptor(target, marker)
	if err != nil {
		t.Fatal(err)
	}
	forgedPtr, err := winpath.UTF16Ptr(forgedPath)
	if err != nil {
		t.Fatal(err)
	}
	forgedAttributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: forgedDescriptor}

	restricted, err := createWindowsManagedRuntimeRestrictedToken()
	if err != nil {
		if errors.Is(err, windows.ERROR_PROC_NOT_FOUND) || errors.Is(err, windows.ERROR_CALL_NOT_IMPLEMENTED) || errors.Is(err, windows.ERROR_NOT_SUPPORTED) {
			t.Skipf("CreateRestrictedToken unavailable: %v", err)
		}
		t.Fatal(err)
	}
	defer restricted.Close() //nolint:errcheck
	runtime.LockOSThread()
	safeUnlock := false
	defer func() {
		if safeUnlock {
			runtime.UnlockOSThread()
		}
	}()
	if err := windows.SetThreadToken(nil, restricted); err != nil {
		t.Fatal(err)
	}
	reverted := false
	defer func() {
		if !reverted {
			if err := windows.RevertToSelf(); err != nil {
				t.Errorf("revert restricted token: %v", err)
				return
			}
		}
		safeUnlock = true
	}()
	assertWindowsManagedRuntimeAdministratorsDisabled(t)
	for _, access := range []uint32{windows.READ_CONTROL, windows.FILE_READ_EA, windows.WRITE_DAC, windows.DELETE} {
		handle, openErr := openWindowsTestDirectoryNoFollowAccess(stagePath, access)
		if openErr == nil && handle != 0 && handle != windows.InvalidHandle {
			_ = windows.CloseHandle(handle)
			t.Fatalf("restricted target opened marker stage with access 0x%x", access)
		}
		if !errors.Is(openErr, windows.ERROR_ACCESS_DENIED) {
			t.Fatalf("restricted stage access 0x%x error=%v, want access denied", access, openErr)
		}
	}
	// Even if a marker value leaked, the restricted target cannot assign that
	// random SID as an object owner without SeRestorePrivilege. This proves the
	// marker-owner claim cannot be fabricated by the enrolled target token.
	if createErr := windows.CreateDirectory(forgedPtr, &forgedAttributes); createErr == nil {
		t.Fatal("restricted target forged a marker-owner staging directory")
	} else if !errors.Is(createErr, windows.ERROR_ACCESS_DENIED) &&
		!errors.Is(createErr, windows.ERROR_INVALID_OWNER) &&
		!errors.Is(createErr, windows.ERROR_PRIVILEGE_NOT_HELD) {
		t.Fatalf("restricted marker-owner create error=%v, want access/owner/privilege denial", createErr)
	}
	if err := windows.RevertToSelf(); err != nil {
		t.Fatal(err)
	}
	reverted = true
	safeUnlock = true

	request := WindowsManagedRuntimeRequest{SchemaVersion: WindowsManagedRuntimeRequestSchemaVersion, Plan: plan, Claims: claims}
	if _, err := CleanupWindowsManagedRuntimeRoots(request, manifest, digest); err != nil {
		t.Fatalf("cleanup restricted-token fixture: %v", err)
	}
}

func TestWindowsManagedRuntimeCleanupAuthenticatesUnjournaledMarkerStage(t *testing.T) {
	target := currentWindowsTestSID(t)
	home := newWindowsManagedRuntimeBAOwnedProfile(t, target)
	manifest := windowsManagedRuntimeTestManifest(home, target)
	digest := strings.Repeat("c", 64)
	plan, err := PlanWindowsManagedRuntimeRoots(manifest, `C:\ProgramData\DefenseClaw\etc\targets.yaml`, digest)
	if err != nil {
		t.Fatal(err)
	}
	rootPlan := plan.Roots[0]
	targetInfo, err := resolveWindowsManagedRuntimeTarget(rootPlan.UserHome, rootPlan.SID, rootPlan.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	err = windowsManagedRuntimeSetupPrivilege(func() error {
		parent, err := openWindowsManagedRuntimeProfile(targetInfo)
		if err != nil {
			return err
		}
		defer windows.CloseHandle(parent)
		marker, err := windows.StringToSid(rootPlan.MarkerSID)
		if err != nil {
			return err
		}
		descriptor, err := windowsManagedRuntimeStagingSecurityDescriptor(targetInfo.sid, marker)
		if err != nil {
			return err
		}
		stage, created, err := openOrCreateWindowsManagedRuntimeStage(parent, rootPlan.StagingLeaf, descriptor)
		if err != nil {
			return err
		}
		defer windows.CloseHandle(stage)
		if !created {
			return errors.New("crash fixture staging root already existed")
		}
		return validateWindowsManagedRuntimeStagingHandle(stage, targetInfo.sid, marker)
	})
	if err != nil {
		t.Fatal(err)
	}
	request := WindowsManagedRuntimeRequest{SchemaVersion: WindowsManagedRuntimeRequestSchemaVersion, Plan: plan}
	if _, err := CleanupWindowsManagedRuntimeRoots(request, manifest, digest); err != nil {
		t.Fatalf("cleanup unjournaled marker stage: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(home, rootPlan.StagingLeaf)); !os.IsNotExist(err) {
		t.Fatalf("unjournaled marker stage survived cleanup: %v", err)
	}
}

func windowsManagedRuntimeTestManifest(home string, target *windows.SID) Manifest {
	return Manifest{Version: 1, Targets: []ManifestTarget{
		{UserHome: home, SID: target.String(), DataDir: filepath.Join(home, ".defenseclaw"), Connector: "codex", AgentVersion: "0.1.0"},
		{UserHome: home, SID: target.String(), DataDir: filepath.Join(home, ".defenseclaw"), Connector: "claudecode", AgentVersion: "2.1.240"},
		{UserHome: home, SID: target.String(), DataDir: filepath.Join(home, ".defenseclaw"), Connector: "cursor", AgentVersion: "1.0.0"},
	}}
}

func writeWindowsManagedRuntimeCleanupFixture(
	t *testing.T,
	root WindowsManagedRuntimeRootPlan,
	target *windows.SID,
	spec windowsManagedRuntimeCleanupSpec,
) []string {
	t.Helper()
	hookDir := filepath.Join(root.DataDir, "hooks")
	if _, err := ensureWindowsTargetOwnedDirectoryTree(root.UserHome, hookDir, target); err != nil {
		t.Fatalf("create exact managed hooks fixture: %v", err)
	}
	var paths []string
	for name := range spec.rootFiles {
		path := filepath.Join(root.DataDir, name)
		if err := os.WriteFile(path, []byte("managed root artifact"), 0o600); err != nil {
			t.Fatal(err)
		}
		setWindowsManagedRuntimeCleanupFileCanonical(t, path, target)
		paths = append(paths, path)
	}
	for name := range spec.hookFiles {
		path := filepath.Join(hookDir, name)
		if err := os.WriteFile(path, []byte("managed hook artifact"), 0o600); err != nil {
			t.Fatal(err)
		}
		setWindowsManagedRuntimeCleanupFileCanonical(t, path, target)
		paths = append(paths, path)
	}
	// Elevated gateway creation may legitimately select BA as the SQLite owner.
	// Preserve the exact protected safe DACL while exercising that owner form.
	inventory := filepath.Join(root.DataDir, "inventory.db")
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	if err := windowsManagedRuntimeSetupPrivilege(func() error {
		extended, err := winpath.Extended(inventory)
		if err != nil {
			return err
		}
		return windows.SetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, administrators, nil, nil, nil)
	}); err != nil {
		t.Fatalf("assign BA gateway inventory owner: %v", err)
	}
	return paths
}

func setWindowsManagedRuntimeCleanupFileCanonical(t *testing.T, path string, target *windows.SID) {
	t.Helper()
	if err := windowsManagedRuntimeSetupPrivilege(func() error {
		extended, err := winpath.Extended(path)
		if err != nil {
			return err
		}
		return windows.SetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, target, nil, nil, nil)
	}); err != nil {
		t.Fatalf("assign exact cleanup fixture owner on %s: %v", path, err)
	}
	if err := setWindowsUserPathProtection(path, target, false); err != nil {
		t.Fatalf("install exact cleanup fixture DACL on %s: %v", path, err)
	}
}

func newWindowsManagedRuntimeBAOwnedProfile(t *testing.T, target *windows.SID) string {
	t.Helper()
	home := newWindowsTargetOwnedTestHome(t, target)
	setWindowsManagedRuntimeBAOwnedProfile(t, home, target)
	return home
}

func newWindowsManagedRuntimeForeignBAOwnedProfile(t *testing.T, target *windows.SID) string {
	t.Helper()
	home := filepath.Join(t.TempDir(), "foreign-home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	setWindowsManagedRuntimeBAOwnedProfile(t, home, target)
	return home
}

func setWindowsManagedRuntimeBAOwnedProfile(t *testing.T, home string, target *windows.SID) {
	t.Helper()
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	const targetProfileAccess windows.ACCESS_MASK = windows.FILE_LIST_DIRECTORY |
		windows.FILE_APPEND_DATA | windows.FILE_TRAVERSE | windows.FILE_READ_ATTRIBUTES |
		windows.READ_CONTROL | windows.SYNCHRONIZE
	dacl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		windowsManagedRuntimeTestAccess(target, targetProfileAccess),
		windowsManagedRuntimeTestAccess(system, 0x001f01ff),
		windowsManagedRuntimeTestAccess(administrators, 0x001f01ff),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		home,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		administrators,
		administrators,
		dacl,
		nil,
	); err != nil {
		t.Fatalf("install BA-owned profile fixture: %v", err)
	}
}

func windowsManagedRuntimeTestAccess(sid *windows.SID, mask windows.ACCESS_MASK) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: mask,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}

func createWindowsManagedRuntimeRestrictedToken() (windows.Token, error) {
	var process windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &process); err != nil {
		return 0, err
	}
	defer process.Close() //nolint:errcheck
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return 0, err
	}
	disabled := windows.SIDAndAttributes{Sid: administrators}
	procedure := windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateRestrictedToken")
	if err := procedure.Find(); err != nil {
		return 0, err
	}
	const disableMaxPrivilege = 0x1
	var primary windows.Token
	result, _, callErr := procedure.Call(
		uintptr(process), disableMaxPrivilege, 1, uintptr(unsafe.Pointer(&disabled)),
		0, 0, 0, 0, uintptr(unsafe.Pointer(&primary)),
	)
	runtime.KeepAlive(disabled)
	if result == 0 {
		if callErr != windows.ERROR_SUCCESS {
			return 0, callErr
		}
		return 0, windows.ERROR_GEN_FAILURE
	}
	defer primary.Close() //nolint:errcheck
	var impersonation windows.Token
	if err := windows.DuplicateTokenEx(primary, windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &impersonation); err != nil {
		return 0, err
	}
	return impersonation, nil
}

func assertWindowsManagedRuntimeAdministratorsDisabled(t *testing.T) {
	t.Helper()
	if err := requireWindowsManagedRuntimeAdministratorsDisabled(); err != nil {
		t.Fatal(err)
	}
}

func requireWindowsManagedRuntimeAdministratorsDisabled() error {
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	groups, err := windows.GetCurrentThreadEffectiveToken().GetTokenGroups()
	if err != nil {
		return err
	}
	for _, group := range groups.AllGroups() {
		if group.Sid != nil && group.Sid.Equals(administrators) {
			if group.Attributes&windows.SE_GROUP_ENABLED != 0 || group.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY == 0 {
				return fmt.Errorf("Administrators attributes=0x%x, want deny-only", group.Attributes)
			}
			return nil
		}
	}
	return nil
}

func runWindowsManagedRuntimeRestrictedToken(token windows.Token, fn func() error) error {
	if token == 0 || fn == nil {
		return errors.New("restricted target token and callback are required")
	}
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := windows.SetThreadToken(nil, token); err != nil {
			runtime.UnlockOSThread()
			result <- err
			return
		}
		callErr := fn()
		revertErr := windows.RevertToSelf()
		if revertErr == nil {
			runtime.UnlockOSThread()
		}
		if callErr != nil {
			result <- callErr
			return
		}
		if revertErr != nil {
			result <- fmt.Errorf("revert restricted target token: %w", revertErr)
			return
		}
		result <- nil
	}()
	return <-result
}

func windowsManagedRuntimePathMutationDenied(err error) bool {
	return errors.Is(err, windows.ERROR_ACCESS_DENIED) ||
		errors.Is(err, windows.ERROR_SHARING_VIOLATION) ||
		errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD)
}

func withWindowsManagedRuntimeRestrictedTarget(t *testing.T, fn func()) {
	t.Helper()
	if fn == nil {
		t.Fatal("restricted target callback is required")
	}
	restricted, err := createWindowsManagedRuntimeRestrictedToken()
	if err != nil {
		if errors.Is(err, windows.ERROR_PROC_NOT_FOUND) || errors.Is(err, windows.ERROR_CALL_NOT_IMPLEMENTED) || errors.Is(err, windows.ERROR_NOT_SUPPORTED) {
			t.Skipf("CreateRestrictedToken unavailable: %v", err)
		}
		t.Fatal(err)
	}
	defer restricted.Close() //nolint:errcheck
	runtime.LockOSThread()
	safeUnlock := false
	defer func() {
		if safeUnlock {
			runtime.UnlockOSThread()
		}
	}()
	if err := windows.SetThreadToken(nil, restricted); err != nil {
		t.Fatal(err)
	}
	reverted := false
	defer func() {
		if !reverted {
			if err := windows.RevertToSelf(); err != nil {
				t.Errorf("revert restricted target token: %v", err)
				return
			}
		}
		safeUnlock = true
	}()
	assertWindowsManagedRuntimeAdministratorsDisabled(t)
	fn()
	if err := windows.RevertToSelf(); err != nil {
		t.Fatal(err)
	}
	reverted = true
	safeUnlock = true
}
