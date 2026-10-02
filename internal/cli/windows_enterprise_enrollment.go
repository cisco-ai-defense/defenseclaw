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
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// windowsEnterpriseEnrollmentAccounts lists each enrolled account and the
// state of each of its connectors in the guardian's last reconcile, so
// status names them (GAP-1073: the security_incomplete warning pointed at
// "each account's detail", which status did not show).
func windowsEnterpriseEnrollmentAccounts(rows []enterpriseHookReconcileRow) []enterprisestatus.EnrollmentAccount {
	var accounts []enterprisestatus.EnrollmentAccount
	// The first failure of each account names why it failed.
	failures := map[string]string{}
	for _, row := range rows {
		key := windowsEnterpriseEnrollmentKey(row.SID, row.User, row.UserHome)
		if !row.OK && !row.Pending && strings.TrimSpace(row.Error) != "" && failures[key] == "" {
			failures[key] = strings.TrimSpace(row.Connector) + ": " + boundedEnterpriseHookUserCleanupText(strings.TrimSpace(row.Error))
		}
	}
	for _, entry := range enterpriseHookEnrollmentFromRows(rows) {
		account := enterprisestatus.EnrollmentAccount{
			Account:    strings.TrimSpace(entry.User),
			SID:        strings.TrimSpace(entry.SID),
			Connectors: map[string]string{},
		}
		if account.Account == "" {
			account.Account = strings.TrimSpace(entry.UserHome)
		}
		if account.Account == "" {
			account.Account = account.SID
		}
		pending := false
		for _, connector := range entry.Connectors {
			account.Connectors[connector.Connector] = connector.State
			pending = pending || connector.State == "pending"
		}
		account.Reason = windowsEnterpriseEnrollmentReason(pending, failures[windowsEnterpriseEnrollmentKey(entry.SID, entry.User, entry.UserHome)])
		accounts = append(accounts, account)
	}
	return accounts
}

// writeWindowsEnterpriseEnrollmentAccounts prints one line per enrolled
// account with each connector's state.
func writeWindowsEnterpriseEnrollmentAccounts(output io.Writer, accounts []enterprisestatus.EnrollmentAccount) {
	for _, account := range accounts {
		label := account.Account
		if account.SID != "" && account.SID != label {
			label += " (" + account.SID + ")"
		}
		names := make([]string, 0, len(account.Connectors))
		for name := range account.Connectors {
			names = append(names, name)
		}
		sort.Strings(names)
		states := make([]string, 0, len(names))
		for _, name := range names {
			states = append(states, name+" "+account.Connectors[name])
		}
		fmt.Fprintf(output, "  Account %s: %s\n", label, strings.Join(states, ", "))
		if account.Reason != "" {
			fmt.Fprintf(output, "    %s\n", account.Reason)
		}
	}
}

// windowsEnterpriseEnrollmentKey groups rows by account the way
// enterpriseHookEnrollmentFromRows does.
func windowsEnterpriseEnrollmentKey(sid, user, home string) string {
	if key := strings.TrimSpace(sid); key != "" {
		return key
	}
	if key := strings.TrimSpace(user); key != "" {
		return key
	}
	return strings.TrimSpace(home)
}

// windowsEnterpriseEnrollmentPending is why an account's connector is
// pending: the guardian acts as a user only in an active (connected)
// session, so a signed-in account with a disconnected session waits too
// (docs: enrollment, "Signed-in session"; GAP-1733).
const windowsEnterpriseEnrollmentPending = "pending: waiting for an active (connected) session of this account; " +
	"its agents are not guarded until then, and a signed-out or disconnected session keeps waiting"

// windowsEnterpriseEnrollmentReason says why an account is not fully
// enrolled, or "" when it is.
func windowsEnterpriseEnrollmentReason(pending bool, failure string) string {
	var reasons []string
	if pending {
		reasons = append(reasons, windowsEnterpriseEnrollmentPending)
	}
	if failure != "" {
		reasons = append(reasons, "failed: "+failure)
	}
	return strings.Join(reasons, "; ")
}
