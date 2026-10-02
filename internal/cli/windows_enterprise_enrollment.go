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
		for _, connector := range entry.Connectors {
			account.Connectors[connector.Connector] = connector.State
		}
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
	}
}
