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
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// Status lists each enrolled account and each connector's state (GAP-1073).
func TestWindowsEnterpriseEnrollmentAccounts(t *testing.T) {
	accounts := windowsEnterpriseEnrollmentAccounts([]enterpriseHookReconcileRow{
		{User: "dcw-std2", SID: "S-1-5-21-1-2-3-1002", Connector: "copilot", Pending: true},
		{User: "dcw-std1", SID: "S-1-5-21-1-2-3-1001", Connector: "codex", OK: true},
		{User: "dcw-std1", SID: "S-1-5-21-1-2-3-1001", Connector: "claudecode", OK: true},
		{SID: "S-1-5-21-1-2-3-1003", Connector: "codex", Error: "profile gone"},
	})
	var out bytes.Buffer
	writeWindowsEnterpriseEnrollmentAccounts(&out, accounts)
	// GAP-1733: a pending or failed account names why.
	want := "  Account dcw-std1 (S-1-5-21-1-2-3-1001): claudecode enrolled, codex enrolled\n" +
		"  Account dcw-std2 (S-1-5-21-1-2-3-1002): copilot pending\n" +
		"    " + windowsEnterpriseEnrollmentPending + "\n" +
		"  Account S-1-5-21-1-2-3-1003: codex failed\n" +
		"    failed: codex: profile gone\n"
	if out.String() != want {
		t.Fatalf("accounts:\n%s\nwant:\n%s", out.String(), want)
	}
	if len(accounts) != 3 || accounts[0].Connectors["codex"] != "enrolled" || accounts[0].Reason != "" ||
		!strings.Contains(accounts[1].Reason, "active (connected) session") {
		t.Fatalf("accounts = %+v", accounts)
	}
}

func TestWindowsEnterpriseEnrollmentDoesNotClaimHermesSessionHomeCoverage(t *testing.T) {
	accounts := windowsEnterpriseEnrollmentAccounts([]enterpriseHookReconcileRow{
		{User: "dcw-std1", SID: "S-1-5-21-1-2-3-1001", Connector: "hermes", OK: true},
		{User: "dcw-std1", SID: "S-1-5-21-1-2-3-1001", Connector: "codex", OK: true},
		{User: "dcw-std2", SID: "S-1-5-21-1-2-3-1002", Connector: "hermes", OK: true},
	})
	if len(accounts) != 2 {
		t.Fatalf("accounts = %+v", accounts)
	}
	for _, account := range accounts {
		if account.Connectors["hermes"] != "enrolled" ||
			!strings.Contains(account.Reason, "NOT COVERED") ||
			!strings.Contains(account.Reason, "session-only HERMES_HOME") {
			t.Fatalf("Hermes registration was presented as coverage for %s: %+v", account.Account, account)
		}
	}
}

// GAP-1243: status and verify name the accounts and groups the config's
// exclude lists hold out, in text and JSON, so an excluded account is not
// mistaken for one that is not enrolled yet.
func TestWindowsEnterpriseStatusNamesTheAccountsExcludeUsersHoldsOut(t *testing.T) {
	body := []byte(`enterprise:
  enrollment:
    exclude_users: ['DCLAB\dcad-w5w3', ' ', alice@corp.example]
    exclude_groups: ['DCLAB\contractors']
`)
	users, groups, err := windowsEnterpriseEnrollmentExclusions(body)
	if err != nil {
		t.Fatal(err)
	}
	enrollment := enterprisestatus.Enrollment{ExcludedUsers: users, ExcludedGroups: groups}
	var text bytes.Buffer
	writeWindowsEnterpriseEnrollmentExclusions(&text, enrollment)
	for _, want := range []string{`exclude_users (not enrolled; their agents are refused at start): DCLAB\dcad-w5w3, alice@corp.example`, `exclude_groups (members are not enrolled): DCLAB\contractors`} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("text %q lacks %q", text.String(), want)
		}
	}
	encoded, err := json.Marshal(enrollment)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"excluded_users":["DCLAB\\dcad-w5w3","alice@corp.example"]`) || !strings.Contains(string(encoded), `"excluded_groups":["DCLAB\\contractors"]`) {
		t.Errorf("json %s does not list the exclusions", encoded)
	}
	if users, groups, err := windowsEnterpriseEnrollmentExclusions([]byte("enterprise: {}\n")); err != nil || users != nil || groups != nil {
		t.Errorf("no exclusions: got %v %v %v", users, groups, err)
	}
}
