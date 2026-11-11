// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// stubWindowsEnterpriseRuntimeFolder replaces the canonical checks of the
// runtime folder repair: assess answers seen, the in-place refusal answers
// refusal, and ensure answers ensured/ensureErr and counts its calls.
func stubWindowsEnterpriseRuntimeFolder(t *testing.T, seen managed.CanonicalResult, refusal error, ensured managed.CanonicalResult, ensureErr error) *int {
	t.Helper()
	assess, refuse, ensure := windowsEnterpriseRuntimeFolderAssess, windowsEnterpriseRuntimeFolderRefuse, windowsEnterpriseRuntimeFolderEnsure
	t.Cleanup(func() {
		windowsEnterpriseRuntimeFolderAssess, windowsEnterpriseRuntimeFolderRefuse, windowsEnterpriseRuntimeFolderEnsure = assess, refuse, ensure
	})
	calls := 0
	windowsEnterpriseRuntimeFolderAssess = func(string, managed.ObjectKind, managed.CanonicalOptions) (managed.CanonicalResult, error) {
		return seen, nil
	}
	windowsEnterpriseRuntimeFolderRefuse = func(string, managed.ObjectKind) error { return refusal }
	windowsEnterpriseRuntimeFolderEnsure = func(string, managed.ObjectKind, managed.CanonicalOptions) (managed.CanonicalResult, error) {
		calls++
		return ensured, ensureErr
	}
	return &calls
}

// A trusted-only drift ensure saw is never reported as compliant (GAP-0573,
// GAP-1048 lane): put back by Setup or by the guardian between the check and
// the repair it is a change; not put back, it is named.
func TestWindowsEnterpriseRuntimeFolderDriftSeenIsNeverCompliant(t *testing.T) {
	const dir = `C:\ProgramData\Cisco\DefenseClaw\runtime`
	drifted := managed.CanonicalResult{Outcome: managed.CanonicalAccepted, Drift: []string{"extra entry S-1-5-32-545"}}
	for _, tc := range []struct {
		name          string
		ensured       managed.CanonicalResult
		ensureErr     error
		change, issue string
	}{
		{name: "repaired by ensure", ensured: managed.CanonicalResult{Outcome: managed.CanonicalRepaired, Drift: drifted.Drift}, change: "restored the access control of " + dir},
		{name: "put back by the guardian meanwhile", ensured: managed.CanonicalResult{Outcome: managed.CanonicalOK}, change: "was put back while ensure repaired it"},
		{name: "still drifted", ensured: managed.CanonicalResult{Outcome: managed.CanonicalAccepted, RepairError: "descriptor still drifted after repair"}, issue: "descriptor still drifted after repair"},
		{name: "repair failed", ensureErr: errors.New("open failed"), issue: "open failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubWindowsEnterpriseRuntimeFolder(t, drifted, nil, tc.ensured, tc.ensureErr)
			change, problem := repairWindowsEnterpriseRuntimeFolder(dir, managed.CanonicalOptions{})
			if tc.change == "" && change != "" || tc.change != "" && !strings.Contains(change, tc.change) {
				t.Fatalf("change %q, want %q", change, tc.change)
			}
			if tc.issue == "" && problem != "" || tc.issue != "" && !strings.Contains(problem, tc.issue) {
				t.Fatalf("problem %q, want %q", problem, tc.issue)
			}
			if tc.issue != "" && !strings.Contains(problem, "extra entry S-1-5-32-545") {
				t.Fatalf("problem %q does not name the drift", problem)
			}
		})
	}
}

// Benign twin and the GAP-1048 protection: a canonical folder is not
// touched, and a folder another account can write is never repaired in
// place (the strict trust walk refuses and names it).
func TestWindowsEnterpriseRuntimeFolderCanonicalOrUntrustedIsNotRepaired(t *testing.T) {
	const dir = `C:\ProgramData\Cisco\DefenseClaw\runtime`
	repaired := managed.CanonicalResult{Outcome: managed.CanonicalRepaired}
	for _, tc := range []struct {
		name    string
		seen    managed.CanonicalResult
		refusal error
	}{
		{name: "canonical", seen: managed.CanonicalResult{Outcome: managed.CanonicalOK}},
		{name: "untrusted writer", seen: managed.CanonicalResult{Outcome: managed.CanonicalBoundary, UntrustedWriters: []string{"S-1-5-32-545"}}},
		{name: "refused in place", seen: managed.CanonicalResult{Outcome: managed.CanonicalAccepted}, refusal: errors.New("refused")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := stubWindowsEnterpriseRuntimeFolder(t, tc.seen, tc.refusal, repaired, nil)
			change, problem := repairWindowsEnterpriseRuntimeFolder(dir, managed.CanonicalOptions{})
			if change != "" || problem != "" || *calls != 0 {
				t.Fatalf("change %q problem %q ensure calls %d, want none", change, problem, *calls)
			}
		})
	}
}

// A drift ensure could not put back is a warning of the run, once across
// the re-planned passes.
func TestWindowsEnterpriseEnsureNamesARuntimeDriftItCouldNotPutBack(t *testing.T) {
	original := windowsEnterpriseRepairDataDirBeforePlan
	originalGuardian := windowsEnterpriseGuardianRepairsSinceLastRun
	t.Cleanup(func() {
		windowsEnterpriseRepairDataDirBeforePlan = original
		windowsEnterpriseGuardianRepairsSinceLastRun = originalGuardian
	})
	windowsEnterpriseRepairDataDirBeforePlan = func() (string, string) { return "", "could not put it back" }
	windowsEnterpriseGuardianRepairsSinceLastRun = func() []string { return nil }
	result := newWindowsEnterpriseStandaloneResult("ensure", &windowsEnterpriseLifecycleOptions{})
	repaired := false
	noteWindowsEnterpriseEnsureDriftRepairs(result, &repaired)
	noteWindowsEnterpriseEnsureDriftRepairs(result, &repaired)
	count := 0
	for _, warning := range result.Warnings {
		if warning.Code == "runtime_acl_not_repaired" {
			count++
		}
	}
	if repaired || count != 1 || len(result.Changes) != 0 {
		t.Fatalf("repaired=%t warnings=%d changes=%v", repaired, count, result.Changes)
	}
}
