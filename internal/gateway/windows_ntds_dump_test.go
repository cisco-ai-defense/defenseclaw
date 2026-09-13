// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

const windowsNTDSIFMDumpRuleID = "credential.windows_ntds_ifm_dump"

func TestWindowsNTDSIFMDumpSemanticOwner(t *testing.T) {
	owner := semanticOwners[windowsNTDSIFMDumpRuleID]
	if owner.prerequisite == nil || owner.detectionOnly || owner.alertOnly {
		t.Fatalf("owner posture = %+v", owner)
	}
	input := actionfacts.Input{
		Tool:        "shell",
		Command:     `ntdsutil "ac i ntds" "ifm" "create full C:\Windows\Temp\ntds" q q`,
		DialectHint: actionfacts.DialectCMD,
	}
	facts := actionfacts.Analyze(input)
	if !owner.eligible(facts) {
		t.Fatalf("exact NTDS IFM export not owned: %+v", facts)
	}
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input: input, LegacyText: input.Command, EnforcementCapable: true,
	})
	matched := findingWithID(findings, windowsNTDSIFMDumpRuleID)
	if matched == nil || matched.Severity != "HIGH" || matched.Evidence != "" {
		t.Fatalf("semantic finding = %+v; all = %v", matched, FindingStrings(findings))
	}
}

func TestWindowsNTDSIFMDumpSafeNegatives(t *testing.T) {
	for _, command := range []string{
		`ntdsutil "set dsrm password" "sync from domain account administrator" q q`,
		`ntdsutil "ac i ntds" "ifm" "create full relative-output" q q`,
		`ntdsutil "ac i ntds" "ifm" "create rodc C:\Windows\Temp\ntds" q q`,
	} {
		input := actionfacts.Input{Tool: "shell", Command: command, CWD: `C:\repo`, DialectHint: actionfacts.DialectCMD}
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: input, LegacyText: command, EnforcementCapable: true,
		})
		if findingWithID(findings, windowsNTDSIFMDumpRuleID) != nil {
			t.Fatalf("safe negative %q produced findings %v", command, FindingStrings(findings))
		}
	}
}
