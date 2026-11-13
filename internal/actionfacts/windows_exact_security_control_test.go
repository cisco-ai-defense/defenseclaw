// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

func TestExactWindowsSecurityControlMutations(t *testing.T) {
	tests := []struct {
		name      string
		command   string
		dialect   Dialect
		operation WindowsSecurityControlMutation
	}{
		{
			name:      "Defender executable extension exclusion",
			command:   `Add-MpPreference -ExclusionExtension ".exe" -Force`,
			dialect:   DialectPowerShell,
			operation: WindowsDefenderExecutableExtensionExclusion,
		},
		{
			name:      "Defender canonical drive root exclusion",
			command:   `Set-MpPreference -ExclusionPath "C:\" -Force`,
			dialect:   DialectPowerShell,
			operation: WindowsDefenderDriveRootExclusion,
		},
		{
			name:      "audit Detailed Tracking failures disabled",
			command:   `auditpol /set /category:"Detailed Tracking" /failure:disable`,
			dialect:   DialectCMD,
			operation: WindowsAuditDetailedTrackingFailureDisable,
		},
		{
			name:      "audit Process Creation successes disabled",
			command:   `auditpol /set /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030} /success:disable`,
			dialect:   DialectCMD,
			operation: WindowsAuditProcessCreationSuccessDisable,
		},
		{
			name:      "full privilege auditing disabled",
			command:   `auditpol /set /option:FullPrivilegeAuditing /value:disable`,
			dialect:   DialectCMD,
			operation: WindowsAuditFullPrivilegeDisable,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{
				Tool:        "shell",
				Command:     test.command,
				CWD:         `C:\repo`,
				DialectHint: test.dialect,
			})
			if !facts.Authoritative() {
				t.Fatalf("facts are not authoritative: %+v", facts.Parse)
			}
			if !ExactWindowsSecurityControlMutation(facts, test.operation) {
				t.Fatalf("operation %q missing: %+v", test.operation, facts.WindowsSecurityControlMutations)
			}
			if got := ExactWindowsSecurityControlMutations(facts); len(got) != 1 ||
				got[0].Operation != test.operation || !got[0].Exact {
				t.Fatalf("mutations=%+v", got)
			}
			if len(facts.Commands) != 1 ||
				!hasFactOperation(facts.Commands[0], OperationConfigChange) ||
				!hasFactOperation(facts.Commands[0], OperationPolicyBypass) {
				t.Fatalf("command semantics=%+v", facts.Commands)
			}
			if got := facts.EnforcementProjection().WindowsSecurityControlMutations; len(got) != 0 {
				t.Fatalf("detection-only mutation leaked into enforcement projection: %+v", got)
			}
		})
	}
}

func TestExactWindowsSecurityControlMutationsStructuredArgv(t *testing.T) {
	for _, test := range []struct {
		name      string
		argv      []string
		dialect   Dialect
		operation WindowsSecurityControlMutation
	}{
		{
			name:      "PowerShell argv",
			argv:      []string{"Add-MpPreference", "-ExclusionExtension", ".exe", "-Force"},
			dialect:   DialectPowerShell,
			operation: WindowsDefenderExecutableExtensionExclusion,
		},
		{
			name:      "CMD argv",
			argv:      []string{"auditpol.exe", "/set", "/option:FullPrivilegeAuditing", "/value:disable"},
			dialect:   DialectCMD,
			operation: WindowsAuditFullPrivilegeDisable,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "shell", Argv: test.argv, DialectHint: test.dialect})
			if !ExactWindowsSecurityControlMutation(facts, test.operation) {
				t.Fatalf("operation %q missing: parse=%+v commands=%+v mutations=%+v", test.operation, facts.Parse, facts.Commands, facts.WindowsSecurityControlMutations)
			}
		})
	}
}

func TestExactWindowsSecurityControlMutationNearNegatives(t *testing.T) {
	tests := []struct {
		name    string
		command string
		dialect Dialect
	}{
		{"Defender read", `Get-MpPreference`, DialectPowerShell},
		{"Defender named directory exclusion", `Add-MpPreference -ExclusionPath "C:\Temp" -Force`, DialectPowerShell},
		{"Defender narrow extension exclusion", `Add-MpPreference -ExclusionExtension ".dll" -Force`, DialectPowerShell},
		{"Defender named process exclusion", `Add-MpPreference -ExclusionProcess "builder.exe" -Force`, DialectPowerShell},
		{"Defender non-root path exclusion", `Set-MpPreference -ExclusionPath "C:\Temp" -Force`, DialectPowerShell},
		{"Defender drive relative path", `Set-MpPreference -ExclusionPath "C:" -Force`, DialectPowerShell},
		{"Defender UNC root", `Set-MpPreference -ExclusionPath "\\server\share\" -Force`, DialectPowerShell},
		{"Defender variable extension", `Add-MpPreference -ExclusionExtension $extension -Force`, DialectPowerShell},
		{"Defender variable path", `Set-MpPreference -ExclusionPath $drive -Force`, DialectPowerShell},
		{"Defender splatting", `Add-MpPreference @params`, DialectPowerShell},
		{"Defender dynamic wrapper", `Invoke-Expression 'Add-MpPreference -ExclusionExtension ".exe" -Force'`, DialectPowerShell},
		{"Defender invocation operator", `& Add-MpPreference -ExclusionExtension ".exe" -Force`, DialectPowerShell},
		{"Defender nested PowerShell", `powershell -Command 'Add-MpPreference -ExclusionExtension ".exe" -Force'`, DialectPowerShell},
		{"audit read", `auditpol /get /category:*`, DialectCMD},
		{"audit restoration", `auditpol /set /category:"Detailed Tracking" /failure:enable`, DialectCMD},
		{"audit other category", `auditpol /set /category:"Account Logon" /failure:disable`, DialectCMD},
		{"audit other subcategory", `auditpol /set /subcategory:{0CCE9210-69AE-11D9-BED3-505054503030} /success:disable`, DialectCMD},
		{"audit variable category", `auditpol /set /category:%CATEGORY% /failure:disable`, DialectCMD},
		{"audit PowerShell variable", `auditpol /set /category:$category /failure:disable`, DialectPowerShell},
		{"audit dynamic wrapper", `cmd.exe /c "auditpol /set /option:FullPrivilegeAuditing /value:disable"`, DialectCMD},
		{"firewall inspection", `netsh advfirewall show allprofiles`, DialectCMD},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "shell", Command: test.command, CWD: `C:\repo`, DialectHint: test.dialect})
			if got := ExactWindowsSecurityControlMutations(facts); len(got) != 0 {
				t.Fatalf("near negative minted exact mutations: %+v; parse=%+v commands=%+v", got, facts.Parse, facts.Commands)
			}
		})
	}
}
