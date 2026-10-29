// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"regexp"
	"strings"
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
