// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

func TestProvesWindowsDefenderDisablement(t *testing.T) {
	for _, test := range []struct {
		name    string
		dialect Dialect
		argv    []string
		want    bool
	}{
		{
			name:    "remove all Defender definitions",
			dialect: DialectCMD,
			argv: []string{`C:\Program Files\Windows Defender\MpCmdRun.exe`,
				"-RemoveDefinitions", "-All"},
			want: true,
		},
		{
			name:    "DISM disable and remove Defender",
			dialect: DialectCMD,
			argv: []string{"Dism", "/online", "/Disable-Feature",
				"/FeatureName:Windows-Defender", "/Remove", "/NoRestart", "/quiet"},
			want: true,
		},
		{
			name:    "PowerShell disable Defender optional feature",
			dialect: DialectPowerShell,
			argv: []string{"Disable-WindowsOptionalFeature", "-Online", "-FeatureName",
				"Windows-Defender", "-NoRestart", "-ErrorAction", "Ignore"},
			want: true,
		},
		{
			name:    "PowerShell remove Defender feature",
			dialect: DialectPowerShell,
			argv:    []string{"Uninstall-WindowsFeature", "-Name", "Windows-Defender"},
			want:    true,
		},
		{
			name:    "delete exact Defender scheduled task",
			dialect: DialectCMD,
			argv: []string{"schtasks", "/delete", "/tn",
				`\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan`, "/f"},
			want: true,
		},
		{
			name:    "sinkhole exact Defender endpoint",
			dialect: DialectPowerShell,
			argv: []string{"Add-DnsClientNrptRule", "-Namespace",
				".endpoint.security.microsoft.com", "-NameServers", "127.0.0.1",
				"-Comment", "Silenced by Name Resolution Policy Table"},
			want: true,
		},
		{
			name:    "definition update",
			dialect: DialectCMD,
			argv: []string{`C:\Program Files\Windows Defender\MpCmdRun.exe`,
				"-SignatureUpdate"},
		},
		{
			name:    "remove only dynamic definitions",
			dialect: DialectCMD,
			argv: []string{`C:\Program Files\Windows Defender\MpCmdRun.exe`,
				"-RemoveDefinitions", "-DynamicSignatures"},
		},
		{
			name:    "lookalike definition tool",
			dialect: DialectCMD,
			argv:    []string{`C:\Temp\MpCmdRun.exe`, "-RemoveDefinitions", "-All"},
		},
		{
			name:    "DISM enable Defender",
			dialect: DialectCMD,
			argv: []string{"Dism", "/online", "/Enable-Feature",
				"/FeatureName:Windows-Defender", "/All", "/NoRestart", "/quiet"},
		},
		{
			name:    "DISM disable unrelated feature",
			dialect: DialectCMD,
			argv: []string{"Dism", "/online", "/Disable-Feature",
				"/FeatureName:TelnetClient", "/Remove", "/NoRestart", "/quiet"},
		},
		{
			name:    "PowerShell enable Defender feature",
			dialect: DialectPowerShell,
			argv: []string{"Enable-WindowsOptionalFeature", "-Online", "-FeatureName",
				"Windows-Defender", "-NoRestart"},
		},
		{
			name:    "PowerShell disable Defender GUI only",
			dialect: DialectPowerShell,
			argv: []string{"Disable-WindowsOptionalFeature", "-Online", "-FeatureName",
				"Windows-Defender-Gui", "-NoRestart"},
		},
		{
			name:    "PowerShell preview Defender disable",
			dialect: DialectPowerShell,
			argv: []string{"Disable-WindowsOptionalFeature", "-Online", "-FeatureName",
				"Windows-Defender", "-NoRestart", "-WhatIf"},
		},
		{
			name:    "create Defender scheduled task",
			dialect: DialectCMD,
			argv: []string{"schtasks", "/create", "/tn",
				`\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan`, "/f"},
		},
		{
			name:    "delete unrelated scheduled task",
			dialect: DialectCMD,
			argv: []string{"schtasks", "/delete", "/tn",
				`\Microsoft\Windows\DiskCleanup\SilentCleanup`, "/f"},
		},
		{
			name:    "delete Defender task without force",
			dialect: DialectCMD,
			argv: []string{"schtasks", "/delete", "/tn",
				`\Microsoft\Windows\Windows Defender\Windows Defender Cleanup`},
		},
		{
			name:    "nonsecurity NRPT rule",
			dialect: DialectPowerShell,
			argv: []string{"Add-DnsClientNrptRule", "-Namespace", "corp.example.com",
				"-NameServers", "127.0.0.1"},
		},
		{
			name:    "Defender endpoint to ordinary resolver",
			dialect: DialectPowerShell,
			argv: []string{"Add-DnsClientNrptRule", "-Namespace",
				"endpoint.security.microsoft.com", "-NameServers", "10.0.0.53"},
		},
		{
			name:    "dynamic NRPT namespace",
			dialect: DialectPowerShell,
			argv: []string{"Add-DnsClientNrptRule", "-Namespace", "#{namespace}",
				"-NameServers", "127.0.0.1"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := windowsSecurityParityTestFacts(test.dialect, test.argv)
			if got := ProvesWindowsDefenderDisablement(facts); got != test.want {
				t.Fatalf("proof=%t want=%t facts=%#v", got, test.want, facts)
			}
		})
	}
}

func TestProvesWindowsUACPolicySuppression(t *testing.T) {
	for _, test := range []struct {
		name string
		argv []string
		want bool
	}{
		{
			name: "disable UAC",
			argv: []string{"Set-ItemProperty",
				`HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
				"-Name", "EnableLUA", "-Value", "0", "-Type", "DWord", "-Force"},
			want: true,
		},
		{
			name: "suppress administrator consent prompt",
			argv: []string{"New-ItemProperty", "-Path",
				`HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
				"-Name", "ConsentPromptBehaviorAdmin", "-PropertyType", "DWORD",
				"-Value", "0", "-Force"},
			want: true,
		},
		{
			name: "disable secure desktop prompt",
			argv: []string{"Set-ItemProperty",
				`HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
				"-Name", "PromptOnSecureDesktop", "-Value", "0", "-Type", "Dword", "-Force"},
			want: true,
		},
		{
			name: "restore UAC",
			argv: []string{"Set-ItemProperty",
				`HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
				"-Name", "EnableLUA", "-Value", "1", "-Type", "DWord", "-Force"},
		},
		{
			name: "restore administrator prompt",
			argv: []string{"Set-ItemProperty",
				`HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
				"-Name", "ConsentPromptBehaviorAdmin", "-Value", "5", "-Type", "DWord", "-Force"},
		},
		{
			name: "unrelated UAC value",
			argv: []string{"Set-ItemProperty",
				`HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
				"-Name", "FilterAdministratorToken", "-Value", "0", "-Type", "DWord", "-Force"},
		},
		{
			name: "wrong registry hive",
			argv: []string{"Set-ItemProperty",
				`HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
				"-Name", "EnableLUA", "-Value", "0", "-Type", "DWord", "-Force"},
		},
		{
			name: "wrong registry key",
			argv: []string{"Set-ItemProperty",
				`HKLM:\SOFTWARE\Acme\Policies\System`, "-Name", "EnableLUA",
				"-Value", "0", "-Type", "DWord", "-Force"},
		},
		{
			name: "dynamic value",
			argv: []string{"Set-ItemProperty",
				`HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
				"-Name", "EnableLUA", "-Value", "$state", "-Type", "DWord", "-Force"},
		},
		{
			name: "placeholder value",
			argv: []string{"Set-ItemProperty",
				`HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
				"-Name", "EnableLUA", "-Value", "#{state}", "-Type", "DWord", "-Force"},
		},
		{
			name: "string coercion",
			argv: []string{"Set-ItemProperty",
				`HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
				"-Name", "EnableLUA", "-Value", "0", "-Type", "String", "-Force"},
		},
		{
			name: "missing force",
			argv: []string{"Set-ItemProperty",
				`HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
				"-Name", "EnableLUA", "-Value", "0", "-Type", "DWord"},
		},
		{
			name: "preview",
			argv: []string{"Set-ItemProperty",
				`HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
				"-Name", "EnableLUA", "-Value", "0", "-Type", "DWord", "-Force", "-WhatIf"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := windowsSecurityParityTestFacts(DialectPowerShell, test.argv)
			if test.name == "dynamic value" {
				facts.Commands[0].Arguments[5].Expands = true
			}
			if got := ProvesWindowsUACPolicySuppression(facts); got != test.want {
				t.Fatalf("proof=%t want=%t facts=%#v", got, test.want, facts)
			}
		})
	}
}

func TestProvesWindowsUACPolicySuppressionFromAnalyze(t *testing.T) {
	for _, command := range []string{
		`Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name PromptOnSecureDesktop -Value 0 -Type Dword -Force`,
		`New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -PropertyType DWORD -Value 0 -Force`,
	} {
		facts := Analyze(Input{
			Tool: "shell", Command: command, CWD: `C:\repo`, DialectHint: DialectPowerShell,
		})
		if !facts.Authoritative() || !facts.EnforcementEligible() ||
			!ProvesWindowsUACPolicySuppression(facts) {
			t.Fatalf("analyzed Atomic-style command did not complete proof: %#v", facts)
		}
	}
}

func TestWindowsSecurityControlParityRequiresCompleteEnforcementFacts(t *testing.T) {
	base := windowsSecurityParityTestFacts(DialectCMD, []string{
		`C:\Program Files\Windows Defender\MpCmdRun.exe`, "-RemoveDefinitions", "-All",
	})
	mutations := map[string]func(*Facts){
		"partial parse": func(facts *Facts) { facts.Parse.Status = StatusPartial },
		"preview":       func(facts *Facts) { facts.Commands[0].Effect = EffectPreview },
		"conditional":   func(facts *Facts) { facts.Commands[0].ControlFlowUncertain = true },
		"incomplete argv": func(facts *Facts) {
			facts.Commands[0].ArgvComplete = false
		},
		"pipeline": func(facts *Facts) { facts.Commands[0].PipelineID = 1 },
		"wrapper": func(facts *Facts) {
			facts.Commands[0].Wrappers = []WrapperFact{{Executable: "cmd.exe"}}
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			facts := base
			facts.Commands = append([]CommandFact(nil), base.Commands...)
			mutate(&facts)
			if ProvesWindowsDefenderDisablement(facts) {
				t.Fatalf("unsafe facts completed proof: %#v", facts)
			}
		})
	}
}

func windowsSecurityParityTestFacts(dialect Dialect, argv []string) Facts {
	arguments := make([]ArgumentFact, 0, len(argv))
	for _, value := range argv {
		arguments = append(arguments, ArgumentFact{Value: value, Quote: QuoteNone})
	}
	return Facts{
		Parse: ParseResult{Status: StatusComplete, Dialect: dialect},
		Commands: []CommandFact{{
			ID:           1,
			Kind:         CommandKindProcess,
			Dialect:      dialect,
			Effect:       EffectExecute,
			Executable:   windowsExecutable(argv[0]),
			Program:      commandProgramForDialect(argv[0], dialect),
			Argv:         append([]string(nil), argv...),
			Arguments:    arguments,
			ArgvComplete: true,
		}},
	}
}
