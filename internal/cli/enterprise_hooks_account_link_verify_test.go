// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import "testing"

func TestGAP0193VerifyAccountLinkGuidance(t *testing.T) {
	const linkFailure = "enterprise hooks: the account's own DefenseClaw folder link is pending repair"
	row := enterpriseHookReconcileRow{
		User: "alice", SID: "S-1-5-21-1-2-3-1001", Connector: "claudecode", Error: linkFailure,
	}
	run := enterpriseHookVerifyRun{Rows: []enterpriseHookReconcileRow{row}, Failures: 1,
		Excused: []enterpriseHookReconcileRow{row}}
	const wantNote = " (the account remains pending until its DefenseClaw folder link is repaired)"
	if note := enterpriseHookVerifyExcusedNote(run, row); note != wantNote {
		t.Fatalf("verify text note = %q, want %q", note, wantNote)
	}
	warnings := enterpriseHookVerifyWarnings(run, nil)
	wantWarning := "claudecode@S-1-5-21-1-2-3-1001: " + linkFailure + wantNote
	if len(warnings) != 1 || warnings[0] != wantWarning {
		t.Fatalf("verify JSON warnings = %q, want %q", warnings, wantWarning)
	}

	removed := row
	removed.Error = "the local account was removed"
	if note := enterpriseHookVerifyExcusedNote(run, removed); note != enterpriseHookRemovedAccountNote {
		t.Fatalf("removed-account note = %q, want %q", note, enterpriseHookRemovedAccountNote)
	}

	foreign := row
	foreign.Error = enterpriseHookAccountForeignLinkFailure
	const wantForeign = " (the account stays unprotected until an administrator removes the link at its DefenseClaw folder)"
	if note := enterpriseHookVerifyExcusedNote(run, foreign); note != wantForeign {
		t.Fatalf("foreign-link verify note = %q, want %q", note, wantForeign)
	}
}
