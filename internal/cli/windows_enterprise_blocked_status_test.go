// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"
)

// GAP-1026: a pending account's Claude Code, Codex and Cursor are refused by
// their machine hooks, so status and verify say "blocked", not only "not
// guarded"; a connector with nothing running keeps the old wording; the
// Secure Client status never reaches this builder.
func TestWindowsEnterprisePendingMachineHookConnectorsAreNamedAsBlocked(t *testing.T) {
	const sid = "S-1-5-21-1-2-3-1001"
	// The account was enrolled before for Claude Code, Codex and Cursor (the
	// guardian's hook configuration is in its folder), never for Copilot or Hermes.
	home := t.TempDir()
	for _, connector := range []string{"claudecode", "codex", "cursor"} {
		enrollMarker(t, home, connector)
	}
	row := func(connector string) enterpriseHookReconcileRow {
		return enterpriseHookReconcileRow{User: "dcw-std1", UserHome: home, SID: sid, Connector: connector, Pending: true}
	}
	reason := func(connectors ...string) string {
		var rows []enterpriseHookReconcileRow
		for _, connector := range connectors {
			rows = append(rows, row(connector))
		}
		accounts := windowsEnterpriseEnrollmentAccounts(rows)
		if len(accounts) != 1 {
			t.Fatalf("accounts = %+v", accounts)
		}
		return accounts[0].Reason
	}

	blocked := windowsEnterpriseEnrollmentPendingLead +
		"claudecode, codex, cursor: " + windowsEnterpriseEnrollmentBlocked
	if got := reason("claudecode", "codex", "cursor"); got != blocked {
		t.Fatalf("machine hook connectors: %q, want %q", got, blocked)
	}
	for _, text := range []string{"blocked until this account signs in or reconnects", "refuses every tool call"} {
		if !strings.Contains(blocked, text) {
			t.Fatalf("reason %q lacks %q", blocked, text)
		}
	}
	// A row that waits for another cause has its runtime: its hook decides, so
	// it is not named as blocked.
	for _, cause := range []string{
		enterpriseHookAwaitingSignInFailOpen, enterpriseHookAwaitingSignInFailClosed, enterpriseHookAwaitingSignInUntrustedFolder,
	} {
		waiting := enterpriseHookReconcileRow{
			User: "dcw-std1", SID: sid, Connector: "codex",
			Error: enterpriseHookAwaitingSignInPrefix + ": " + cause + ": detail",
		}
		accounts := windowsEnterpriseEnrollmentAccounts([]enterpriseHookReconcileRow{waiting})
		if len(accounts) != 1 || strings.Contains(accounts[0].Reason, "blocked") || accounts[0].Connectors["codex"] != "pending" {
			t.Fatalf("cause %q: %+v, want pending and not named as blocked", cause, accounts)
		}
	}
	// A never-enrolled account (no marker) keeps the old wording for the same
	// connectors (GAP-1010).
	neverEnrolled := func(connectors ...string) string {
		var rows []enterpriseHookReconcileRow
		for _, connector := range connectors {
			rows = append(rows, enterpriseHookReconcileRow{User: "dcw-new", UserHome: t.TempDir(), SID: sid + "9", Connector: connector, Pending: true})
		}
		return windowsEnterpriseEnrollmentAccounts(rows)[0].Reason
	}
	if got := neverEnrolled("claudecode", "codex", "cursor"); got != windowsEnterpriseEnrollmentPending {
		t.Fatalf("a never-enrolled account: %q, want the old wording", got)
	}
	// A row with no profile folder recorded cannot be judged enrolled.
	if got := windowsEnterpriseEnrollmentAccounts([]enterpriseHookReconcileRow{
		{User: "dcw-x", SID: sid + "8", Connector: "codex", Pending: true}})[0].Reason; got != windowsEnterpriseEnrollmentPending {
		t.Fatalf("a row without a folder: %q", got)
	}
	if got := reason("copilot"); got != windowsEnterpriseEnrollmentPending {
		t.Fatalf("a connector with nothing running keeps the old reason: %q", got)
	}
	if got, want := reason("cursor", "copilot"), windowsEnterpriseEnrollmentPendingLead+
		"cursor: "+windowsEnterpriseEnrollmentBlocked+"; copilot: "+windowsEnterpriseEnrollmentUnguarded; got != want {
		t.Fatalf("mixed account: %q, want %q", got, want)
	}
}
