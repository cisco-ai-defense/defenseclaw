// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

// Every connector row of an own-status answer that is not "protected" says
// why and what the account holder can do next. The launcher prints the row
// next to the connector name, so the text does not repeat the name.
//
// The rows are built here and nowhere else: ownNotProtected and
// ownNotConfirmed take a cause, and a cause is a sentence that names the
// reason and the next step. A row with no cause cannot be built.
const (
	// ownCauseNoSetup: the guardian record is readable and holds no hook
	// install for this account and connector. An agent that is installed
	// but failing is in the unprotected-agents scan with its own reason, so
	// what is left is an agent with nothing set up for the account yet.
	ownCauseNoSetup = "DefenseClaw has not set up protection for this agent on your account. " +
		"If you do not have it installed, install it and run defenseclaw status again in a few minutes; " +
		"if it is installed and stays this way, ask IT"
	// ownCauseRootDenied: policy denies the root account.
	ownCauseRootDenied = "your organization's policy does not allow DefenseClaw to run for the root account. " +
		"Use your own account, or ask IT"
	// ownCauseUnprovenSource: the vendor policy sources for this connector
	// could not be proven for this account.
	ownCauseUnprovenSource = "DefenseClaw cannot prove your organization's settings for this agent on this account, " +
		"so its tool calls are not trusted as checked. Ask IT"
	// ownCauseNotEnrolled: strict policy and the account is not enrolled.
	ownCauseNotEnrolled = "your account is not enrolled in your organization's DefenseClaw policy for this agent. " +
		"Ask IT to enroll it"
	// ownCauseNoGuardianRecord: no enrollment record could be read.
	ownCauseNoGuardianRecord = "DefenseClaw cannot read the enrollment record for your account right now. " +
		"Run defenseclaw status again in a few minutes, and ask IT if it stays this way"
	// ownCauseScanUnknown: the enumerator's last scan is missing, old or
	// from another install or config.
	ownCauseScanUnknown = "DefenseClaw has no recent protection check for this computer. " +
		"Run defenseclaw status again in a few minutes, and ask IT if it stays this way"
	// ownCauseScanUnmatched: the administrator status lists an agent that may
	// be the caller's but cannot be matched to the account.
	ownCauseScanUnmatched = "the administrator status lists an agent here that cannot be matched to your account. " +
		"Ask IT to check it"
	// ownCauseWindowsUnchecked: the Windows own-status pipe carries no
	// per-connector hook proof for any connector but Claude Code.
	ownCauseWindowsUnchecked = "your account's status cannot check this agent. " +
		"Ask IT to run the administrator status for this computer"
	// ownScanNextStep follows the recorded reason of every row the scan lists
	// as unprotected for the account, whatever the reason says.
	ownScanNextStep = "Run defenseclaw status again in a few minutes, and ask IT if it stays this way"
	// ownCauseNoUnprotectedReason: the scan lists the agent as unprotected
	// but recorded no reason text.
	ownCauseNoUnprotectedReason = "the administrator status lists this agent as unprotected for your account. Ask IT"
)

func ownNotProtected(cause string) map[string]any {
	return map[string]any{"protected": false, "state": "not protected: " + cause}
}

func ownNotConfirmed(cause string) map[string]any {
	return map[string]any{"protected": false, "state": "not confirmed: " + cause}
}

func ownProtected() map[string]any {
	return map[string]any{"protected": true, "state": "protected"}
}
