// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"
)

// GAP-0980 wording: a signed-out account's status says only what is true of
// each connector. Copilot, Antigravity and Kiro run the previous release's
// per-user hook; Claude Code and Codex (hook fail mode open) have this
// release's machine hook in place and wait only for the account's
// registration; a connector with nothing running is not guarded until the
// account signs in.
const (
	g980Lead     = "pending: waiting for an active (connected) session of this account; "
	g980Previous = "the previous release's DefenseClaw hook keeps running until this account signs in and the guardian updates it"
	g980Machine  = "the machine hook is in place and the account's registration finishes when it signs in"
	g980Unguard  = "not guarded until this account signs in"
)

const (
	g980User = `HOST\dcw-std1`
	g980SID  = "S-1-5-21-1-2-3-1020"
)

func g980Row(connector, cause string) enterpriseHookReconcileRow {
	return enterpriseHookReconcileRow{
		User: g980User, SID: g980SID, Connector: connector,
		Error: enterpriseHookAwaitingSignInPrefix + ": " + cause + ": DefenseClaw 1.0.5 protected it (verification: x)",
	}
}

func g980Reason(t *testing.T, rows ...enterpriseHookReconcileRow) string {
	t.Helper()
	accounts := windowsEnterpriseEnrollmentAccounts(rows)
	if len(accounts) != 1 {
		t.Fatalf("accounts = %+v, want one", accounts)
	}
	return accounts[0].Reason
}

func TestWindowsEnterpriseEnrollmentReasonPriorRenderOnly(t *testing.T) {
	prior := enterpriseHookAwaitingSignInPriorRender
	reason := g980Reason(t, g980Row("copilot", prior), g980Row("kiro", prior), g980Row("antigravity", prior),
		enterpriseHookReconcileRow{User: g980User, SID: g980SID, Connector: "cursor", OK: true})
	if want := g980Lead + g980Previous + ": copilot, kiro, antigravity"; reason != want {
		t.Fatalf("reason %q, want %q", reason, want)
	}
	if strings.Contains(reason, "machine hook") || strings.Contains(reason, "not guarded") {
		t.Fatalf("reason %q claims more than the previous release's hook", reason)
	}
}

func TestWindowsEnterpriseEnrollmentReasonMachineHookOnly(t *testing.T) {
	newUpgradeWaitFixture(t) // standalone config for enterpriseHookAwaitingSignInRow
	open := enterpriseHookAwaitingSignInOpenMode
	reason := g980Reason(t, g980Row("claudecode", open), g980Row("codex", open))
	if want := g980Lead + g980Machine + ": claudecode, codex"; reason != want {
		t.Fatalf("reason %q, want %q", reason, want)
	}
	if strings.Contains(reason, "previous release") || strings.Contains(reason, "not guarded") {
		t.Fatalf("reason %q claims the previous release's hook or no guard", reason)
	}
	row := g980Row("codex", open)
	if enterpriseHookAwaitingSignInKeepsRunningRow(row) || !enterpriseHookAwaitingSignInMachineHookRow(row) ||
		!enterpriseHookAwaitingSignInRow(row) || enterpriseHookEarlierMatrixRow(row) {
		t.Fatalf("row %+v is not read as the machine hook in place", row)
	}
	state := enterpriseHookGuardianState{Version: 1, TargetCount: 1, FailureCount: 1, Results: []enterpriseHookReconcileRow{row}}
	if removed, awaiting, linked := enterpriseHookExcusedFailures(state); removed != 0 || awaiting != 1 || linked != 0 {
		t.Fatalf("excused failures = %d removed, %d awaiting, %d linked; want 1 awaiting", removed, awaiting, linked)
	}
	for name, text := range map[string]string{
		"cause": enterpriseHookAwaitingSignInCause(row.Error),
		"issue": enterpriseHookGuardianFailureIssue(row),
	} {
		if !strings.Contains(text, "machine hook is in place") || strings.Contains(text, "previous release") ||
			strings.Contains(text, "not guarded") {
			t.Fatalf("%s %q", name, text)
		}
	}
}

func TestWindowsEnterpriseEnrollmentReasonMixedNamesEachGroup(t *testing.T) {
	prior, open := enterpriseHookAwaitingSignInPriorRender, enterpriseHookAwaitingSignInOpenMode
	waiting := func(connector string) enterpriseHookReconcileRow {
		return enterpriseHookReconcileRow{User: g980User, SID: g980SID, Connector: connector, Pending: true}
	}
	for _, tc := range []struct {
		name string
		rows []enterpriseHookReconcileRow
		want string
	}{
		{
			"nothing running and the previous hook",
			[]enterpriseHookReconcileRow{waiting("devin"), waiting("amp"), g980Row("copilot", prior), g980Row("kiro", prior)},
			g980Lead + "devin, amp: " + g980Unguard + "; copilot, kiro: " + g980Previous,
		},
		{
			"nothing running and the machine hook",
			[]enterpriseHookReconcileRow{waiting("devin"), g980Row("claudecode", open)},
			g980Lead + "devin: " + g980Unguard + "; claudecode: " + g980Machine,
		},
		{
			"the previous hook and the machine hook",
			[]enterpriseHookReconcileRow{g980Row("copilot", prior), g980Row("codex", open)},
			g980Lead + "copilot: " + g980Previous + "; codex: " + g980Machine,
		},
		{
			"all three",
			[]enterpriseHookReconcileRow{waiting("devin"), g980Row("copilot", prior), g980Row("codex", open)},
			g980Lead + "devin: " + g980Unguard + "; copilot: " + g980Previous + "; codex: " + g980Machine,
		},
	} {
		if reason := g980Reason(t, tc.rows...); reason != tc.want {
			t.Fatalf("%s: reason %q, want %q", tc.name, reason, tc.want)
		}
	}
	// A failure of another connector follows the pending text.
	failed := enterpriseHookReconcileRow{User: g980User, SID: g980SID, Connector: "cursor", Error: "boom"}
	if reason, want := g980Reason(t, g980Row("copilot", prior), failed), g980Lead+g980Previous+": copilot; failed: cursor: boom"; reason != want {
		t.Fatalf("with a failure: reason %q, want %q", reason, want)
	}
}

// Secure Client keeps the generic pending text word for word, and a pending
// account with nothing but unguarded connectors still gets it.
func TestWindowsEnterpriseEnrollmentPendingTextIsUnchanged(t *testing.T) {
	const want = "pending: waiting for an active (connected) session of this account; " +
		"its agents are not guarded until then, and a signed-out or disconnected session keeps waiting"
	if windowsEnterpriseEnrollmentPending != want {
		t.Fatalf("windowsEnterpriseEnrollmentPending = %q, want %q", windowsEnterpriseEnrollmentPending, want)
	}
	reason := g980Reason(t, enterpriseHookReconcileRow{User: g980User, SID: g980SID, Connector: "devin", Pending: true})
	if reason != want {
		t.Fatalf("reason %q, want the unchanged generic text", reason)
	}
}
