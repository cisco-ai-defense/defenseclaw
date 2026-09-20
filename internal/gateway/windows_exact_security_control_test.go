// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func TestWindowsExactSecurityControlStrictDetectionOnlyPosture(t *testing.T) {
	tests := []struct {
		name      string
		ruleID    string
		command   string
		dialect   actionfacts.Dialect
		operation actionfacts.WindowsSecurityControlMutation
	}{
		{"Defender executable extension", "defense_evasion.windows_defender_executable_exclusion", `Add-MpPreference -ExclusionExtension ".exe" -Force`, actionfacts.DialectPowerShell, actionfacts.WindowsDefenderExecutableExtensionExclusion},
		{"Defender drive root", "defense_evasion.windows_defender_drive_root_exclusion", `Set-MpPreference -ExclusionPath "C:\" -Force`, actionfacts.DialectPowerShell, actionfacts.WindowsDefenderDriveRootExclusion},
		{"audit Detailed Tracking failures", "tamper.windows_audit_detailed_tracking_failure_disable", `auditpol /set /category:"Detailed Tracking" /failure:disable`, actionfacts.DialectCMD, actionfacts.WindowsAuditDetailedTrackingFailureDisable},
		{"audit Process Creation successes", "tamper.windows_audit_process_creation_success_disable", `auditpol /set /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030} /success:disable`, actionfacts.DialectCMD, actionfacts.WindowsAuditProcessCreationSuccessDisable},
		{"audit full privilege", "tamper.windows_audit_full_privilege_disable", `auditpol /set /option:FullPrivilegeAuditing /value:disable`, actionfacts.DialectCMD, actionfacts.WindowsAuditFullPrivilegeDisable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := actionfacts.Input{
				Tool: "shell", Command: test.command, CWD: `C:\repo`, DialectHint: test.dialect,
			}
			facts := actionfacts.Analyze(input)
			if !actionfacts.ExactWindowsSecurityControlMutation(facts, test.operation) {
				t.Fatalf("exact operation %q missing: %+v", test.operation, facts)
			}
			owner, ok := semanticOwners[test.ruleID]
			if !ok || owner.prerequisite == nil || !owner.detectionOnly || owner.alertOnly ||
				!owner.eligible(facts) {
				t.Fatalf("semantic owner posture=%+v exists=%t", owner, ok)
			}

			// The regex is deliberately inert; only the typed semantic path may
			// materialize these findings.
			if findingWithID(scanTrustedRulesForProfile(t, "strict", test.command, "shell"), test.ruleID) != nil {
				t.Fatalf("raw text scanner authorized %s", test.ruleID)
			}

			for _, profile := range []string{"default", "permissive", "strict"} {
				connector := "windows-exact-security-" + profile
				installToolCallCorpusProfileConnector(t, connector, profile)
				findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
					Input: input, LegacyText: test.command, Connector: connector, EnforcementCapable: true,
				})
				finding := findingWithID(findings, test.ruleID)
				if profile != "strict" {
					if finding != nil {
						t.Fatalf("profile %s unexpectedly found %+v", profile, *finding)
					}
					continue
				}
				if finding == nil || finding.Severity != "HIGH" || finding.Evidence != "" ||
					finding.contributesToEnforcement() {
					t.Fatalf("strict finding=%+v all=%v", finding, FindingStrings(findings))
				}
			}
		})
	}
}

func TestWindowsExactSecurityControlNearNegativesStayQuiet(t *testing.T) {
	const connector = "windows-exact-security-near-negatives"
	installToolCallCorpusProfileConnector(t, connector, "strict")
	ruleIDs := []string{
		"defense_evasion.windows_defender_executable_exclusion",
		"defense_evasion.windows_defender_drive_root_exclusion",
		"tamper.windows_audit_detailed_tracking_failure_disable",
		"tamper.windows_audit_process_creation_success_disable",
		"tamper.windows_audit_full_privilege_disable",
	}
	for _, test := range []struct {
		command string
		dialect actionfacts.Dialect
	}{
		{`Get-MpPreference`, actionfacts.DialectPowerShell},
		{`Add-MpPreference -ExclusionPath "C:\Temp" -Force`, actionfacts.DialectPowerShell},
		{`Add-MpPreference -ExclusionExtension ".dll" -Force`, actionfacts.DialectPowerShell},
		{`Add-MpPreference -ExclusionProcess "builder.exe" -Force`, actionfacts.DialectPowerShell},
		{`Set-MpPreference -ExclusionPath "C:\Temp" -Force`, actionfacts.DialectPowerShell},
		{`Add-MpPreference -ExclusionExtension $extension -Force`, actionfacts.DialectPowerShell},
		{`Set-MpPreference -ExclusionPath $drive -Force`, actionfacts.DialectPowerShell},
		{`Add-MpPreference @params`, actionfacts.DialectPowerShell},
		{`Invoke-Expression 'Add-MpPreference -ExclusionExtension ".exe" -Force'`, actionfacts.DialectPowerShell},
		{`& Add-MpPreference -ExclusionExtension ".exe" -Force`, actionfacts.DialectPowerShell},
		{`powershell -Command 'Add-MpPreference -ExclusionExtension ".exe" -Force'`, actionfacts.DialectPowerShell},
		{`auditpol /get /category:*`, actionfacts.DialectCMD},
		{`auditpol /set /category:"Detailed Tracking" /failure:enable`, actionfacts.DialectCMD},
		{`auditpol /set /category:%CATEGORY% /failure:disable`, actionfacts.DialectCMD},
		{`netsh advfirewall show allprofiles`, actionfacts.DialectCMD},
	} {
		input := actionfacts.Input{Tool: "shell", Command: test.command, CWD: `C:\repo`, DialectHint: test.dialect}
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: input, LegacyText: test.command, Connector: connector, EnforcementCapable: true,
		})
		for _, ruleID := range ruleIDs {
			if finding := findingWithID(findings, ruleID); finding != nil {
				t.Fatalf("near negative %q matched %s: %+v", test.command, ruleID, *finding)
			}
		}
	}
}
