// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// A connector the administrator took off the roster reads "not managed
// (removed from roster)" in every renderer: never protected, never pending.

func removedConnectorFixture() []managed.RemovedConnector {
	return []managed.RemovedConnector{
		{Connector: "cursor", SID: "S-1-5-21-1-2-3-1002", User: `HOST\bob`, RemovedAt: "2026-11-08T18:00:00Z"},
		{Connector: "codex", SID: "S-1-5-21-1-2-3-1001", User: `HOST\alice`, RemovedAt: "2026-11-08T18:00:00Z"},
		{Connector: "cursor", SID: "S-1-5-21-1-2-3-1001", UserHome: `C:\Users\alice`, RemovedAt: "2026-11-08T18:00:00Z"},
	}
}

func TestWindowsEnterpriseStatusRendersARemovedConnectorAsNotManaged(t *testing.T) {
	accounts := windowsEnterpriseRemovedConnectorAccounts(removedConnectorFixture())
	if len(accounts) != 2 || accounts[0].SID != "S-1-5-21-1-2-3-1001" || accounts[1].SID != "S-1-5-21-1-2-3-1002" {
		t.Fatalf("accounts = %+v", accounts)
	}
	if accounts[0].Account != `HOST\alice` || accounts[1].Account != `HOST\bob` {
		t.Fatalf("account labels = %q, %q", accounts[0].Account, accounts[1].Account)
	}
	for _, account := range accounts {
		for name, state := range account.Connectors {
			if state != managed.NotManagedRemovedFromRoster || state == "pending" || state == "enrolled" {
				t.Fatalf("%s %s = %q", account.Account, name, state)
			}
		}
	}
	var out bytes.Buffer
	writeWindowsEnterpriseRemovedConnectors(&out, accounts)
	want := "  Account HOST\\alice (S-1-5-21-1-2-3-1001): codex not managed (removed from roster), cursor not managed (removed from roster)\n" +
		"  Account HOST\\bob (S-1-5-21-1-2-3-1002): cursor not managed (removed from roster)\n"
	if out.String() != want {
		t.Fatalf("status text =\n%q\nwant\n%q", out.String(), want)
	}
	for _, word := range []string{"pending", "protected", "enrolled"} {
		if strings.Contains(out.String(), word) {
			t.Fatalf("a removed connector reads %q: %s", word, out.String())
		}
	}
	// The unlabeled account falls back to its home, then its SID.
	only := windowsEnterpriseRemovedConnectorAccounts([]managed.RemovedConnector{{Connector: "cursor", SID: "S-1-5-21-1-2-3-1005", RemovedAt: "t"}})
	if only[0].Account != "S-1-5-21-1-2-3-1005" {
		t.Fatalf("label = %q", only[0].Account)
	}
	if windowsEnterpriseRemovedConnectorAccounts(nil) != nil {
		t.Fatal("no record gave accounts")
	}
}

func TestManagedWindowsDoctorAndTUIAnswersSayARemovedConnectorIsNotManaged(t *testing.T) {
	restore := managedWindowsRemovedConnectorLines
	t.Cleanup(func() { managedWindowsRemovedConnectorLines = restore })
	const where = "HKLM\\SOFTWARE\\Cisco\\DefenseClaw\\Enterprise"
	managedWindowsRemovedConnectorLines = func() []string { return nil }
	plainDoctor := managedWindowsAdminCommandAnswer(where, "doctor").Error()
	plainTUI := managedWindowsTUIAnswer(where).Error()
	if strings.Contains(plainDoctor, "removed from roster") || strings.Contains(plainTUI, "removed from roster") {
		t.Fatal("an account with nothing removed was told about a removed connector")
	}
	managedWindowsRemovedConnectorLines = func() []string { return []string{"cursor: " + managed.NotManagedRemovedFromRoster} }
	for name, answer := range map[string]string{
		"doctor": managedWindowsAdminCommandAnswer(where, "doctor").Error(),
		"tui":    managedWindowsTUIAnswer(where).Error(),
	} {
		if !strings.Contains(answer, "cursor: not managed (removed from roster)") {
			t.Errorf("%s answer does not say the connector is not managed: %s", name, answer)
		}
		if !strings.Contains(answer, "neither protected nor pending") {
			t.Errorf("%s answer does not say it is neither protected nor pending: %s", name, answer)
		}
		if !strings.HasSuffix(answer, "Nothing was changed.") {
			t.Errorf("%s answer lost its closing sentence: %s", name, answer)
		}
	}
	// status for an elevated prompt is not changed by it.
	if strings.Contains(managedWindowsAdminCommandAnswer(where, "status").Error(), "removed from roster") {
		t.Fatal("the status answer names a removed connector")
	}
	_ = enterprisestatus.Enrollment{}
}
