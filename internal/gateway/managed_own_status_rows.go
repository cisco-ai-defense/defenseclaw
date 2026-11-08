// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"unicode"
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

// ownScanReason is a recorded scan reason as the row shows it: free text with
// the surrounding space and the closing sentence punctuation removed, so a
// reason that is only punctuation is empty.
func ownScanReason(reason string) string {
	return strings.TrimFunc(reason, func(r rune) bool { return r == '.' || unicode.IsSpace(r) })
}

// ownScanCause is the cause of a row the scan lists as unprotected for the
// account: the recorded reasons (free text) and ownScanNextStep. A reason that
// is empty once normalized gives the no-reason cause, so the row always has
// its reason field.
func ownScanCause(reasons string) ownCause {
	reasons = ownScanReason(reasons)
	if reasons == "" {
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

func ownProtected() map[string]any {
	return map[string]any{"protected": true, "state": "protected"}
}

// ownCoworkRow is the Cowork row: the state is protected, not protected, not
// confirmed or refused, and a reason comes with every state but none of them
// has a next step to offer.
func ownCoworkRow(protected bool, state, code, reason string) map[string]any {
	return ownRow(protected, state, ownCause{code: code, reason: reason})
}
