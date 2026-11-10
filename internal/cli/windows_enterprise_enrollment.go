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
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
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
		// A row that waits for its account's next sign-in is pending, not
		// failed (GAP-0644).
		if !row.OK && !row.Pending && !enterpriseHookAwaitingSignInError(row) &&
			strings.TrimSpace(row.Error) != "" && failures[key] == "" {
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
		hermesLimited := false
		var earlier, keepsRunning, machineHook, unguarded []string
		for _, row := range rows {
			if windowsEnterpriseEnrollmentKey(row.SID, row.User, row.UserHome) ==
				windowsEnterpriseEnrollmentKey(entry.SID, entry.User, entry.UserHome) && enterpriseHookEarlierMatrixRow(row) {
				earlier = append(earlier, strings.TrimSpace(row.Connector)+": "+enterpriseHookEarlierMatrixState)
			}
		}
		for _, row := range rows {
			if windowsEnterpriseEnrollmentKey(row.SID, row.User, row.UserHome) !=
				windowsEnterpriseEnrollmentKey(entry.SID, entry.User, entry.UserHome) {
				continue
			}
			switch {
			case enterpriseHookAwaitingSignInKeepsRunningRow(row):
				keepsRunning = append(keepsRunning, strings.TrimSpace(row.Connector))
			case enterpriseHookAwaitingSignInMachineHookRow(row):
				machineHook = append(machineHook, strings.TrimSpace(row.Connector))
			case row.Pending, enterpriseHookAwaitingSignInError(row) && !enterpriseHookEarlierMatrixRow(row):
				unguarded = append(unguarded, strings.TrimSpace(row.Connector))
			}
		}
		for _, connector := range entry.Connectors {
			account.Connectors[connector.Connector] = connector.State
			pending = pending || connector.State == "pending"
			hermesLimited = hermesLimited || connector.Connector == "hermes" && connector.State == "enrolled"
		}
		account.Reason = windowsEnterpriseEnrollmentReason(pending, failures[windowsEnterpriseEnrollmentKey(entry.SID, entry.User, entry.UserHome)])
		if pending && len(keepsRunning)+len(machineHook) > 0 {
			// Some connector that waits is not unguarded (the previous
			// release's hook keeps running, or the machine hook is in place):
			// name each group for what it really has, never the generic
			// "its agents are not guarded" for all of them.
			account.Reason = windowsEnterpriseStandalonePendingReason(unguarded, keepsRunning, machineHook)
			if failure := failures[windowsEnterpriseEnrollmentKey(entry.SID, entry.User, entry.UserHome)]; failure != "" {
				account.Reason += "; failed: " + failure
			}
		}
		// A machine-hook connector (Claude Code, Codex, Cursor) that waits for
		// the sign-in is not merely unguarded: the machine hook is registered
		// for the account and refuses every tool call until the guardian
		// publishes the account's runtime in its connected session
		// (GAP-1026). The reason says so. The only caller is the standalone
		// status (readWindowsEnterpriseStandaloneEnrollmentAt); Secure Client
		// builds its reason elsewhere and keeps it word for word.
		var blocked []string
		for _, row := range rows {
			// Only a row that waits with no runtime at all is blocked: a row
			// that waits for a hook fail mode change, an untrusted folder or
			// another cause is an awaiting-sign-in error, never Pending, has
			// its runtime, and its hook decides.
			if windowsEnterpriseEnrollmentKey(row.SID, row.User, row.UserHome) ==
				windowsEnterpriseEnrollmentKey(entry.SID, entry.User, entry.UserHome) &&
				row.Pending && windowsEnterpriseMachineHookConnector(row.Connector) {
				blocked = append(blocked, strings.TrimSpace(row.Connector))
			}
		}
		if rest := windowsEnterpriseWithout(unguarded, blocked); pending && len(blocked) > 0 {
			account.Reason = windowsEnterpriseStandaloneBlockedPendingReason(blocked, rest, keepsRunning, machineHook)
			if failure := failures[windowsEnterpriseEnrollmentKey(entry.SID, entry.User, entry.UserHome)]; failure != "" {
				account.Reason += "; failed: " + failure
			}
		}
		for _, note := range earlier {
			if account.Reason != "" {
				account.Reason += "; "
			}
			account.Reason += note
		}
		if hermesLimited {
			if limit := enterprisehooks.ManagedHermesSessionHomeAttestation("windows", "hermes", true, false); limit != nil {
				if account.Reason != "" {
					account.Reason += "; "
				}
				account.Reason += "Hermes NOT COVERED: " + limit.Error()
			}
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
		if account.Reason != "" {
			fmt.Fprintf(output, "    %s\n", account.Reason)
		}
	}
}

// windowsEnterpriseRemovedConnectorAccounts groups the record by account: the
// connectors an administrator took off the roster that each account had been
// enrolled for, each "not managed (removed from roster)". They are kept apart
// from the enrolled accounts, so nothing that counts or lists enrolled
// accounts takes a removed connector for one that is enrolled or pending.
func windowsEnterpriseRemovedConnectorAccounts(removed []managed.RemovedConnector) []enterprisestatus.RemovedConnectorAccount {
	var accounts []enterprisestatus.RemovedConnectorAccount
	index := map[string]int{}
	for _, entry := range removed {
		sid := strings.TrimSpace(entry.SID)
		key := strings.ToUpper(sid)
		i, ok := index[key]
		if !ok {
			label := strings.TrimSpace(entry.User)
			if label == "" {
				label = strings.TrimSpace(entry.UserHome)
			}
			if label == "" {
				label = sid
			}
			accounts = append(accounts, enterprisestatus.RemovedConnectorAccount{Account: label, SID: sid, Connectors: map[string]string{}})
			i = len(accounts) - 1
			index[key] = i
		}
		accounts[i].Connectors[strings.ToLower(strings.TrimSpace(entry.Connector))] = managed.NotManagedRemovedFromRoster
	}
	sort.Slice(accounts, func(a, b int) bool { return accounts[a].SID < accounts[b].SID })
	return accounts
}

// writeWindowsEnterpriseRemovedConnectors prints one line per account with
// the connectors removed from the roster.
func writeWindowsEnterpriseRemovedConnectors(output io.Writer, accounts []enterprisestatus.RemovedConnectorAccount) {
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

// The standalone reasons of an account that waits (GAP-0980). They are built
// here and never reuse windowsEnterpriseEnrollmentPending, which Secure Client
// keeps word for word.
const (
	windowsEnterpriseEnrollmentPendingLead = "pending: waiting for an active (connected) session of this account; "
	// The previous release's per-user hook (Copilot, Antigravity, Kiro) runs.
	windowsEnterpriseEnrollmentKeepsRunning = "the previous release's DefenseClaw hook keeps running until this account " +
		"signs in and the guardian updates it"
	// The machine hook (Claude Code, Codex with hook fail mode open) is in place.
	windowsEnterpriseEnrollmentMachineHook = "the machine hook is in place and the account's registration finishes " +
		"when it signs in"
	// Nothing runs for the connector yet.
	windowsEnterpriseEnrollmentUnguarded = "not guarded until this account signs in"
)

// windowsEnterpriseEnrollmentPendingKeepsRunning leads the reason of an account
// whose waiting connectors all still run the previous release's hook; the
// connectors follow.
const windowsEnterpriseEnrollmentPendingKeepsRunning = windowsEnterpriseEnrollmentPendingLead +
	windowsEnterpriseEnrollmentKeepsRunning + ": "

// windowsEnterpriseStandalonePendingReason is the reason of an account that
// waits with at least one connector that is not unguarded. One group alone
// reads "<lead><what it has>: <connectors>"; several groups are each named
// "<connectors>: <what it has>", so the reason never says one thing of all.
func windowsEnterpriseStandalonePendingReason(unguarded, keepsRunning, machineHook []string) string {
	if len(unguarded) == 0 && (len(keepsRunning) == 0 || len(machineHook) == 0) {
		if len(machineHook) == 0 {
			return windowsEnterpriseEnrollmentPendingKeepsRunning + strings.Join(keepsRunning, ", ")
		}
		return windowsEnterpriseEnrollmentPendingLead + windowsEnterpriseEnrollmentMachineHook + ": " +
			strings.Join(machineHook, ", ")
	}
	var groups []string
	for _, group := range []struct {
		connectors []string
		text       string
	}{
		{unguarded, windowsEnterpriseEnrollmentUnguarded},
		{keepsRunning, windowsEnterpriseEnrollmentKeepsRunning},
		{machineHook, windowsEnterpriseEnrollmentMachineHook},
	} {
		if len(group.connectors) > 0 {
			groups = append(groups, strings.Join(group.connectors, ", ")+": "+group.text)
		}
	}
	return windowsEnterpriseEnrollmentPendingLead + strings.Join(groups, "; ")
}

// windowsEnterpriseEnrollmentBlocked is what a pending machine-hook connector
// (Claude Code, Codex, Cursor) has: the hook is in place and refuses every tool
// call, so the agent is blocked, not unprotected, until the account has a
// connected session in which the guardian publishes its runtime (GAP-1026).
const windowsEnterpriseEnrollmentBlocked = "blocked until this account signs in or reconnects " +
	"(DefenseClaw refuses every tool call of the agent)"

// windowsEnterpriseMachineHookConnector reports a connector whose hook is
// registered machine-wide for every enrolled account, so a pending account is
// refused by it (the connectors of RetireWindowsUnregisteredRuntimeSelections).
func windowsEnterpriseMachineHookConnector(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "claudecode", "codex", "cursor":
		return true
	}
	return false
}

// windowsEnterpriseWithout returns names without the entries of drop.
func windowsEnterpriseWithout(names, drop []string) []string {
	var rest []string
	for _, name := range names {
		if !slices.Contains(drop, name) {
			rest = append(rest, name)
		}
	}
	return rest
}

// windowsEnterpriseStandaloneBlockedPendingReason is the reason of a pending
// account with at least one blocked connector: every group is named
// "<connectors>: <what it has>", so the reason never says one thing of all.
func windowsEnterpriseStandaloneBlockedPendingReason(blocked, unguarded, keepsRunning, machineHook []string) string {
	var groups []string
	for _, group := range []struct {
		connectors []string
		text       string
	}{
		{blocked, windowsEnterpriseEnrollmentBlocked},
		{unguarded, windowsEnterpriseEnrollmentUnguarded},
		{keepsRunning, windowsEnterpriseEnrollmentKeepsRunning},
		{machineHook, windowsEnterpriseEnrollmentMachineHook},
	} {
		if len(group.connectors) > 0 {
			groups = append(groups, strings.Join(group.connectors, ", ")+": "+group.text)
		}
	}
	return windowsEnterpriseEnrollmentPendingLead + strings.Join(groups, "; ")
}

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

// windowsEnterpriseEnrollmentExclusions reads enterprise.enrollment's
// exclude_users and exclude_groups from the installed config, so status and
// verify name the accounts held out by policy; the enumerator gives them no
// rows, and without the list an excluded account looked like one not
// enrolled yet (GAP-1243).
func windowsEnterpriseEnrollmentExclusions(configBody []byte) (users, groups []string, err error) {
	var document struct {
		Enterprise struct {
			Enrollment struct {
				ExcludeUsers  []string `yaml:"exclude_users"`
				ExcludeGroups []string `yaml:"exclude_groups"`
			} `yaml:"enrollment"`
		} `yaml:"enterprise"`
	}
	if err := yaml.Unmarshal(configBody, &document); err != nil {
		return nil, nil, err
	}
	clean := func(entries []string) []string {
		var out []string
		for _, entry := range entries {
			if entry = strings.TrimSpace(entry); entry != "" {
				out = append(out, entry)
			}
		}
		return out
	}
	return clean(document.Enterprise.Enrollment.ExcludeUsers), clean(document.Enterprise.Enrollment.ExcludeGroups), nil
}

// writeWindowsEnterpriseEnrollmentExclusions prints the exclusion lists
// after the enrolled accounts.
func writeWindowsEnterpriseEnrollmentExclusions(output io.Writer, enrollment enterprisestatus.Enrollment) {
	if len(enrollment.ExcludedUsers) > 0 {
		fmt.Fprintf(output, "  Excluded by enterprise.enrollment.exclude_users (not enrolled; their agents are refused at start): %s\n", strings.Join(enrollment.ExcludedUsers, ", "))
	}
	if len(enrollment.ExcludedGroups) > 0 {
		fmt.Fprintf(output, "  Excluded by enterprise.enrollment.exclude_groups (members are not enrolled): %s\n", strings.Join(enrollment.ExcludedGroups, ", "))
	}
}
