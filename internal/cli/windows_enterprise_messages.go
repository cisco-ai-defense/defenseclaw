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
)

// Windows enterprise result wording that does not depend on Windows APIs,
// kept here so the unit tests run on every platform.

// windowsEnterpriseNoActiveSession is why LocalSystem could not act as an
// account: Windows gives it a user's token only for an active (connected)
// session, so a signed-in account whose session is disconnected is skipped
// like a signed-out one. "were signed out" sent administrators to quser,
// which showed the account signed in (GAP-1756).
const windowsEnterpriseNoActiveSession = "had no active (connected) session (signed out, or signed in with a disconnected session)"

// windowsEnterpriseActiveSessionWhen is when a LocalSystem rerun can act as
// the accounts.
const windowsEnterpriseActiveSessionWhen = "while the accounts have an active (connected) session (signed in, and reconnected if the session is disconnected)"

// windowsEnterpriseLocalSystemRemedy is the next step for what only a
// LocalSystem run removes: install again, then run the given Setup action,
// both as LocalSystem while the accounts have an active session.
func windowsEnterpriseLocalSystemRemedy(action string) string {
	return "run DefenseClaw Setup /ensure and then " + action + ", both as LocalSystem " + windowsEnterpriseActiveSessionWhen + " " +
		"(an MDM system context, or from an elevated prompt a one-time scheduled task that runs as SYSTEM; " +
		"see \"Run Setup as LocalSystem\" in the Windows enterprise guide)"
}

// windowsManagedHooksPurgedBinariesMarker separates a purged account's label
// in user_state_purged from what the purge removed from that account's
// %USERPROFILE%\.local\bin ("none" when it held no DefenseClaw file).
const windowsManagedHooksPurgedBinariesMarker = ` | .local\bin: `

// windowsManagedHooksPurgedLabel appends to a purged account's label the
// file names its binaries purge removed, so the result does not claim
// binaries an account never had (GAP-1735).
func windowsManagedHooksPurgedLabel(label string, removed []string) string {
	var names []string
	for _, path := range removed {
		path = strings.TrimSpace(path)
		lower := strings.ToLower(path)
		switch {
		case path == "":
			continue
		case strings.HasPrefix(path, "Path entry "):
			names = append(names, "its user Path entry")
		case strings.HasSuffix(lower, `\.local\bin`) || strings.HasSuffix(lower, "/.local/bin"):
			names = append(names, "the emptied folder")
		default:
			names = append(names, path[strings.LastIndexAny(path, `\/`)+1:])
		}
	}
	if len(names) == 0 {
		return label + windowsManagedHooksPurgedBinariesMarker + "none"
	}
	return label + windowsManagedHooksPurgedBinariesMarker + strings.Join(names, ", ")
}

// windowsEnterprisePurgedUserStateChange is the change line for one
// user_state_purged entry. An entry without the marker comes from a helper
// that did not report its binaries.
func windowsEnterprisePurgedUserStateChange(entry string) string {
	account, binaries, found := strings.Cut(entry, windowsManagedHooksPurgedBinariesMarker)
	line := "removed all DefenseClaw per-user data of " + account + " (hook scripts and foreign-hooks-backup included)"
	switch {
	case !found:
		return line + " and any DefenseClaw per-user binaries in %USERPROFILE%\\.local\\bin"
	case binaries == "none":
		return line + "; its %USERPROFILE%\\.local\\bin held no DefenseClaw binaries"
	default:
		return line + " and, from its %USERPROFILE%\\.local\\bin: " + binaries
	}
}

// windowsEnterpriseStandardUserMutationAnswer answers a standard account's
// `enterprise windows install`, `upgrade`, `repair` or `ensure`: only an
// administrator can change the managed deployment (GAP-1961).
func windowsEnterpriseStandardUserMutationAnswer(action string) string {
	return "a standard account cannot " + action + " the managed deployment. Ask your administrator, who runs it from an elevated PowerShell prompt with `& '" +
		managedWindowsAdminCLI() + "' enterprise windows " + action + " --profile standalone`. Nothing was changed."
}

// windowsManagedStandardUserViewAnswer answers a standard account's
// read-only view of a managed Windows deployment (AI Discovery, machine
// policy, audit export) the way status and verify answer it: what the view
// needs, the elevated command to ask the administrator for, and that
// nothing changed. It ran exit 1 with a stuttered internal prefix and no
// command (GAP-2039). The code stays out of the sentence: it is the
// managedViewRefusal's, for --json errors[].code (GAP-2262).
func windowsManagedStandardUserViewAnswer(what, adminArgs string) string {
	return what + " of a managed computer can be read only from an elevated Administrator prompt or by the MDM agent. " +
		"Ask your administrator, who runs it from an elevated PowerShell prompt with `& '" + managedWindowsAdminCLI() + "' " + adminArgs + "`. Nothing was changed."
}

// managedViewRefusal is a standard account's refusal of a managed view. It
// prints as the sentence alone, like status and verify; its code
// (elevation_required) is only for the --json errors[].code. The text read
// "Error: elevation_required: ..." (GAP-2262).
type managedViewRefusal struct {
	code    string
	message string
}

func (r *managedViewRefusal) Error() string { return r.message }

// managedHostCurrentAccountName is the signed-in account without its
// computer or domain prefix: the AI Discovery view names accounts that way,
// and every refusal names it that way in the commands it suggests
// (`enterprise policy show --user` resolves the plain name too), not as
// COMPUTER\account in some and account in others (GAP-2262).
func managedHostCurrentAccountName() string {
	account := managedHostCurrentAccount()
	return account[strings.LastIndex(account, `\`)+1:]
}

// windowsEnterpriseStandardUserInspectionAnswer answers a standard account's
// `enterprise windows status` or `verify`: only an elevated prompt can run
// the installer's integrity checks. The installer's own refusal (an invalid
// module signature, "use -AllowUnsigned") read as a broken deployment and
// gave administrator-only advice (GAP-1720).
func windowsEnterpriseStandardUserInspectionAnswer(action string) string {
	return "the managed deployment's " + action + " needs an elevated prompt: a standard account cannot run the installer's own checks, " +
		"so this says nothing about the deployment's health. Ask your administrator, who checks it from an elevated PowerShell prompt with `& '" +
		managedWindowsAdminCLI() + "' enterprise windows " + action + " --profile standalone`, and your account's agents with `& '" +
		managedWindowsAdminCLI() + "' enterprise policy show --user " + managedHostCurrentAccountName() + "`. Nothing was changed."
}
