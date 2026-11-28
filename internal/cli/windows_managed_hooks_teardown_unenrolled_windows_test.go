// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"reflect"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// GAP-1892: the teardown leaves out of the enrollment it expects exactly the
// failed targets the Guardian left out of what it published: no ledger row.
// A failed target the ledger names, and a per-user-install tamper row, stay
// expected; so does a failed target the state does not record.
func TestGAP1892TeardownLeavesOutOnlyFailedTargetsTheLedgerNeverProtected(t *testing.T) {
	const carol, dave = "S-1-5-21-111-222-333-1003", "S-1-5-21-111-222-333-1004"
	skipped := gap1892Target("claudecode", gap1892Bob, "bob")
	protectedFailed := gap1892Target("claudecode", carol, "carol")
	tamper := gap1892Target("claudecode", dave, "dave")
	unrecorded := gap1892Target("codex", gap1892Bob, "bob")
	state := enterpriseHookGuardianState{Results: []enterpriseHookReconcileRow{
		{SID: gap1892Alice, Connector: "claudecode", OK: true},
		{SID: gap1892Bob, Connector: "claudecode", UserHome: `C:\Users\bob`, Error: enterpriseHookAccountPerUserInstallFailure},
		{SID: carol, Connector: "claudecode", UserHome: `C:\Users\carol`, Error: "enterprise hooks: some failure"},
		{SID: dave, Connector: "claudecode", UserHome: `C:\Users\dave`, Error: enterpriseHookAccountPerUserInstallTamper + " (x)"},
	}}
	authorization := enterpriseHookGuardianAuthorization{ProtectedTargets: []enterpriseHookReconcileRow{
		{SID: gap1892Alice, Connector: "claudecode", UserHome: `C:\Users\alice`, OK: true},
		{SID: carol, Connector: "claudecode", UserHome: `C:\Users\carol`, OK: true},
	}}
	got := windowsManagedHooksTeardownUnenrolledTargets(authorization, state,
		[]windowsManagedHooksTeardownTarget{skipped, protectedFailed, tamper, unrecorded})
	if want := []windowsManagedHooksTeardownTarget{skipped}; !reflect.DeepEqual(got, want) {
		t.Fatalf("unenrolled = %+v, want %+v", got, want)
	}
	// A ledger row of another home does not protect the target.
	moved := enterpriseHookGuardianAuthorization{ProtectedTargets: []enterpriseHookReconcileRow{
		{SID: carol, Connector: "claudecode", UserHome: `C:\Users\elsewhere`, OK: true},
	}}
	if got := windowsManagedHooksTeardownUnenrolledTargets(moved, state, []windowsManagedHooksTeardownTarget{protectedFailed}); len(got) != 1 {
		t.Fatalf("a ledger row of another home protected the target: %+v", got)
	}

	claude, codex, cursor := windowsManagedHooksTeardownWithoutUnenrolled(
		[]windowsManagedHooksTeardownTarget{skipped, gap1892Target("cursor", gap1892Bob, "bob")},
		[]string{gap1892Alice, gap1892Bob},
		[]connector.WindowsCodexManagedRuntimeTarget{{SID: gap1892Bob, DataDir: `C:\Users\bob\.defenseclaw`}},
		[]enterprisehooks.WindowsCursorManagedRuntimeTarget{{SID: gap1892Bob, DataDir: `C:\Users\bob\.defenseclaw`}},
	)
	if !reflect.DeepEqual(claude, []string{gap1892Alice}) || len(codex) != 1 || len(cursor) != 0 {
		t.Fatalf("enrollment = %v %+v %+v, want alice for Claude, bob kept for Codex, none for Cursor", claude, codex, cursor)
	}

	// The per-user rollback republishes the enrollment less the targets the
	// Guardian never enrolled.
	journal := windowsManagedHooksTeardownJournal{
		ActivationState: windowsManagedHooksActivated,
		Targets: []windowsManagedHooksTeardownTarget{
			gap1892Target("copilot", gap1892Alice, "alice"), gap1892Target("copilot", gap1892Bob, "bob"),
		},
		FailedTargets: []windowsManagedHooksTeardownTarget{gap1892Target("copilot", gap1892Bob, "bob")},
		unenrolled:    []windowsManagedHooksTeardownTarget{gap1892Target("copilot", gap1892Bob, "bob")},
	}
	expected := windowsManagedHooksStandalonePerUserExpected(journal)
	if want := []enterprisehooks.WindowsPerUserManagedEnrollmentTarget{{SID: gap1892Alice, DataDir: `C:\Users\alice\.defenseclaw`}}; !reflect.DeepEqual(expected["copilot"], want) {
		t.Fatalf("copilot rollback set = %+v, want %+v", expected["copilot"], want)
	}
}
