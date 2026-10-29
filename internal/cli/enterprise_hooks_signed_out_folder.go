// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// enterpriseHookSignedOutUntrustedFolderPattern is the whole error a
// standalone Windows guardian (1.0.2 and this release) records for a
// protected target whose account is signed out and whose verification failed
// on the owner or permissions of the account's DefenseClaw folder (data) or
// its hooks folder (hook), or, for connectors with managed runtime
// generations (Codex, Copilot), on either folder through the runtime
// generation check or the Hermes footprint check (no group 1, GAP-2516). Keep it equal to $script:SignedOutUntrustedFolderPattern
// in packaging/windows/DefenseClawEnterprise.psm1 (a contract test compares
// them).
var enterpriseHookSignedOutUntrustedFolderPattern = regexp.MustCompile(
	`^enterprise hooks: protected target requires repair but its exact active Windows session is unavailable ` +
		`\(verification: enterprise hooks: (?:managed (data|hook) directory verification failed|managed runtime generation directory is untrusted|footprint directory trust check failed): enterprise hooks: (?:` +
		`managed Windows DACL on (.+) has \d+ ACEs, expected \d+|` +
		`managed Windows DACL is not protected on (.+)|` +
		`managed Windows DACL on (.+) contains unexpected or duplicate ACE for principal S-[0-9-]+ \(mask 0x[0-9a-f]+, inheritance 0x[0-9a-f]+\)|` +
		`managed Windows DACL on (.+) contains non-canonical ACE type at index \d+|` +
		`managed Windows DACL on (.+) contains non-canonical ACE type \d+ at index \d+ \(principal S-[0-9-]+\)|` +
		`owner SID \S+ does not match target SID S-[0-9-]+ on (.+)|` +
		`null or unreadable Windows DACL on (.+))\)$`,
)

// enterpriseHookSignedOutUntrustedFolder returns the DefenseClaw folder of a
// failed guardian row whose only recorded failure is that its account is
// signed out and that folder (dataDir, or dataDir's hooks folder) does not
// carry the owner or permissions DefenseClaw set (#1105, GAP-0211). The
// guardian repairs such a target only in the account's own Windows session,
// at its next sign-in, so no lifecycle run can fix it; an upgrade that
// refused it kept the whole computer on the older release. A connected
// account's row, a folder of another account, a row with runtime evidence or
// any other failure (a link, a missing folder, a file) returns false.
func enterpriseHookSignedOutUntrustedFolder(row enterpriseHookReconcileRow, dataDir string) (string, bool) {
	if row.OK || row.Pending || row.Result != nil {
		return "", false
	}
	dataDir = strings.TrimRight(strings.ReplaceAll(strings.TrimSpace(dataDir), "/", `\`), `\`)
	if dataDir == "" {
		return "", false
	}
	match := enterpriseHookSignedOutUntrustedFolderPattern.FindStringSubmatch(strings.TrimSpace(row.Error))
	if match == nil {
		return "", false
	}
	folder := ""
	for _, group := range match[2:] {
		if group != "" {
			folder = group
			break
		}
	}
	folder = strings.TrimRight(strings.ReplaceAll(folder, "/", `\`), `\`)
	candidates := []string{dataDir}
	switch match[1] {
	case "hook":
		candidates = []string{dataDir + `\hooks`}
	case "":
		// The runtime generation check of a Codex or Copilot target reads
		// both folders.
		candidates = append(candidates, dataDir+`\hooks`)
	}
	for _, expected := range candidates {
		if strings.EqualFold(folder, expected) {
			return expected, true
		}
	}
	return "", false
}

// enterpriseHookSignedOutUntrustedFolderVerifyRow reports a live verify row
// of a managed standalone Windows deferred target that fails only on the
// owner or permissions of its own DefenseClaw folder or hooks folder
// (enterpriseHookSignedOutUntrustedFolder) while its account is signed out
// now, and that the guardian last recorded as protected. It returns the
// sign-in wait the row reports. The guardian classifies the same failure as
// a sign-in wait when it sees it; a folder that changed after the guardian
// last verified the target failed Setup readiness 1603 and then its rollback
// for every user (GAP-2516: the Codex and Copilot rows of the signed-out
// account). The protected records are compared with it as protected, as for
// a signed-out Hermes home. A row the guardian recorded failed or never
// recorded, a connected account, Secure Client, and any other failure are
// unchanged; a session that cannot be queried is never taken as a sign-out.
func enterpriseHookSignedOutUntrustedFolderVerifyRow(
	target enterprisehooks.ManifestTarget,
	row enterpriseHookReconcileRow,
	liveErr error,
	recorded map[string]enterpriseHookReconcileRow,
) (string, bool) {
	if liveErr == nil || !enterpriseHookHermesSignedOutApplies() || !target.IsDeferred() {
		return "", false
	}
	key := enterpriseHookProtectedTargetKey(row)
	if last, known := recorded[key]; key == "" || !known || !last.OK {
		return "", false
	}
	folder, untrusted := enterpriseHookSignedOutUntrustedFolder(enterpriseHookReconcileRow{
		Error: fmt.Sprintf("enterprise hooks: protected target requires repair but its exact active Windows "+
			"session is unavailable (verification: %v)", liveErr),
	}, target.DataDir)
	if !untrusted {
		return "", false
	}
	available, err := enterpriseHookReconcileSessionAvailable(target)
	signedOut := err == nil && !available
	if err != nil && enterpriseHookSessionCheckNotLocalSystem(err) {
		noSession, listErr := enterpriseHookTargetHasNoSession(target)
		signedOut = listErr == nil && noSession
	}
	if !signedOut {
		return "", false
	}
	return fmt.Sprintf("%s: %s: %s; its exact active Windows session is unavailable, so the guardian repairs it at "+
		"the account's next sign-in (verification: %v)",
		enterpriseHookAwaitingSignInPrefix, enterpriseHookAwaitingSignInUntrustedFolder, folder, liveErr), true
}
