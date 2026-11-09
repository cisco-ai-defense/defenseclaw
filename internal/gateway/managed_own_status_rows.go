// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"runtime"
	"strings"
	"unicode"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Every connector row of an own-status answer that is not "protected" says
// why and what the account holder can do next. The launcher prints the row
// next to the connector name, so the text does not repeat the name.
//
// The rows are built here and nowhere else: ownNotProtected and
// ownNotConfirmed take a cause. A row keeps its state to one of the values a
// script can match (protected, not protected, not confirmed); the cause goes
// in separate fields (reason_code, reason, next_step), and the launcher joins
// them into the sentence it prints. A row with no cause cannot be built.

// ownCause is why a row is not protected and what the account holder can do
// next. The reason names no connector and has no trailing period: the
// launcher prints it next to the connector name.
type ownCause struct {
	// code is the stable machine name of the cause.
	code string
	// reason says why, as a sentence fragment.
	reason string
	// next is the next step; empty for a row that has none to offer.
	next string
}

var (
	// ownCauseNoSetup: the guardian record is readable and holds no hook
	// install for this account and connector. An agent that is installed
	// but failing is in the unprotected-agents scan with its own reason, so
	// what is left is an agent with nothing set up for the account yet.
	ownCauseNoSetup = ownCause{"no_setup", "DefenseClaw has not set up protection for this agent on your account",
		"If you do not have it installed, install it and run defenseclaw status again in a few minutes; " +
			"if it is installed and stays this way, ask IT"}
	// ownCauseRootDenied: policy denies the root account.
	ownCauseRootDenied = ownCause{"root_denied", "your organization's policy does not allow DefenseClaw to run for the root account",
		"Use your own account, or ask IT"}
	// ownCauseUnprovenSource: the vendor policy sources for this connector
	// could not be proven for this account.
	ownCauseUnprovenSource = ownCause{"unproven_source",
		"DefenseClaw cannot prove your organization's settings for this agent on this account, so its tool calls are not trusted as checked",
		"Ask IT"}
	// ownCauseNotEnrolled: strict policy and the account is not enrolled.
	ownCauseNotEnrolled = ownCause{"not_enrolled",
		"your account is not enrolled in your organization's DefenseClaw policy for this agent", "Ask IT to enroll it"}
	// ownCauseNoGuardianRecord: no enrollment record could be read.
	ownCauseNoGuardianRecord = ownCause{"no_enrollment_record", "DefenseClaw cannot read the enrollment record for your account right now",
		ownRetryNextStep}
	// ownCauseScanUnknown: the enumerator's last scan is missing, old or
	// from another install or config.
	ownCauseScanUnknown = ownCause{"scan_unknown", "DefenseClaw has no recent protection check for this computer", ownRetryNextStep}
	// ownCauseScanUnmatched: the administrator status lists an agent that may
	// be the caller's but cannot be matched to the account.
	ownCauseScanUnmatched = ownCause{"scan_unmatched",
		"the administrator status lists an agent here that cannot be matched to your account", "Ask IT to check it"}
	// ownCauseWindowsUnchecked: the Windows own-status pipe carries no
	// per-connector hook proof for any connector but Claude Code.
	ownCauseWindowsUnchecked = ownCause{"windows_unchecked", "your account's status cannot check this agent",
		"Ask IT to run the administrator status for this computer"}
	// ownCauseAccountUnresolved: the Windows account could not be named, so
	// whether exclude_users covers it cannot be judged.
	ownCauseAccountUnresolved = ownCause{"account_unresolved",
		"DefenseClaw cannot look up your account name right now, so it cannot check whether your organization's policy covers it",
		ownRetryNextStep}
	// ownCauseNoUnprotectedReason: the scan lists the agent as unprotected
	// but recorded no reason text.
	ownCauseNoUnprotectedReason = ownCause{"scan_no_reason",
		"the administrator status lists this agent as unprotected for your account", "Ask IT"}
)

const (
	// ownRetryNextStep follows a cause that may pass by itself.
	ownRetryNextStep = "Run defenseclaw status again in a few minutes, and ask IT if it stays this way"
	// ownScanNextStep follows the recorded reason of every row the scan lists
	// as unprotected for the account, whatever the reason says.
	ownScanNextStep = ownRetryNextStep
)

// ownScanReason is a recorded scan reason as the row shows it: the recorded
// text byte for byte, minus trailing space. The text is free text (it can
// start with a path such as .claude/settings.json), so nothing at its start is
// removed; a reason with no word in it, only periods and space, is empty.
func ownScanReason(reason string) string {
	reason = strings.TrimRightFunc(reason, unicode.IsSpace)
	if strings.TrimFunc(reason, func(r rune) bool { return r == '.' || unicode.IsSpace(r) }) == "" {
		return ""
	}
	return reason
}

// ownScanCause is the cause of a row the scan lists as unprotected for the
// account: the recorded reasons (free text) and ownScanNextStep. A reason that
// is empty gives the no-reason cause, so the row always has its reason field.
func ownScanCause(reasons string) ownCause {
	if reasons = ownScanReason(reasons); reasons == "" {
		return ownCauseNoUnprotectedReason
	}
	return ownCause{"scan_unprotected", reasons, ownScanNextStep}
}

func ownRow(protected bool, state string, cause ownCause) map[string]any {
	row := map[string]any{"protected": protected, "state": state}
	if cause.code != "" {
		row["reason_code"] = cause.code
	}
	if cause.reason != "" {
		row["reason"] = cause.reason
	}
	if cause.next != "" {
		row["next_step"] = cause.next
	}
	return row
}

func ownNotProtected(cause ownCause) map[string]any {
	return ownRow(false, "not protected", cause)
}

func ownNotConfirmed(cause ownCause) map[string]any {
	return ownRow(false, "not confirmed", cause)
}

// ownInspection is what the status can prove about the calls of an account that
// exclude_users names, for one connector. Exclusion only keeps the account out
// of enrollment; a machine policy runs its hook for every account whatever
// enrollment says. The row claims only what it can back: a pinned machine-policy
// hook, or the absence of any, and otherwise it sends the reader to the
// administrator status (rel-1-0-9 GAP-0949).
type ownInspection int

const (
	// ownInspectionUnknown: the status cannot tell what still inspects the
	// calls (no authorizer, as on the Windows own-status pipe; the account name
	// is not resolved; the vendor source is unreadable or not the pinned one; an
	// admission without a proven hook), so the row claims nothing.
	ownInspectionUnknown ownInspection = iota
	// ownInspectionNone: no machine-policy hook covers the account for the
	// connector, and no admission names it.
	ownInspectionNone
	// ownInspectionInspected: a machine-policy hook for the connector is
	// installed and pinned for the account. Whatever the hook authorizer then
	// answers (inspect, refuse), the machine policy is what handles the calls.
	ownInspectionInspected
)

const (
	ownExcludedBase = "your account is listed in enterprise.enrollment.exclude_users: excluded from enrollment"
)

// ownExcludedNextStep names the administrator rule and the command that shows
// it. Setup puts no DefenseClaw command on the PATH of a Windows computer, so
// there the command is the managed CLI by its path, in PowerShell (GAP-0979).
func ownExcludedNextStep() string {
	command := "defenseclaw-gateway enterprise policy show --user <account>"
	if runtime.GOOS == "windows" {
		command = managed.WindowsAdminCommand("enterprise", "policy", "show", "--user", "<account>")
	}
	return "Ask IT to remove your account from enterprise.enrollment.exclude_users; " + command + " shows the rule"
}

// ownExcludedCause is the reason of an excluded row: the exclusion, and what
// the status can prove about the calls. The state stays excluded whatever the
// inspection is; the reason is in its own field.
func ownExcludedCause(inspection ownInspection) ownCause {
	cause := ownCause{"excluded_users", ownExcludedBase, ownExcludedNextStep()}
	switch inspection {
	case ownInspectionNone:
		cause.reason += "; DefenseClaw does not inspect your calls"
	case ownInspectionInspected:
		cause.code = "excluded_users_inspected"
		cause.reason += "; the machine policy still inspects your calls"
	default:
		cause.code = "excluded_users_unverified"
		cause.reason += "; to see what still inspects calls, an administrator runs " + managed.AdminStatusHint(runtime.GOOS)
	}
	return cause
}

// ownExcluded is the row of an account that exclude_users names: a state of
// its own, never protected and never the machine-wide state.
func ownExcluded(inspection ownInspection) map[string]any {
	return ownRow(false, "excluded", ownExcludedCause(inspection))
}

func ownProtected() map[string]any {
	return map[string]any{"protected": true, "state": "protected"}
}

// ownCoworkRow is the Cowork row: the state is protected, not protected, not
// confirmed or refused, and a reason comes with every state but none of them
// has a next step to offer.
func ownCoworkRow(protected bool, state, code, reason string) map[string]any {
	return ownRow(protected, state, ownCause{code: code, reason: reason})
}
