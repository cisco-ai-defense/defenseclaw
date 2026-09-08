// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

func TestExactWindowsTelemetryDisable(t *testing.T) {
	for _, test := range []struct {
		name    string
		command string
		dialect Dialect
		want    bool
	}{
		{name: "CMD user COMPlus ETW", command: `REG ADD HKCU\Environment /v COMPlus_ETWEnabled /t REG_SZ /d 0 /f`, dialect: DialectCMD, want: true},
		{name: "CMD machine COMPlus ETW", command: `REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v COMPlus_ETWEnabled /t REG_SZ /d 0 /f`, dialect: DialectCMD, want: true},
		{name: "PowerShell user COMPlus ETW", command: `New-ItemProperty -Path HKCU:\Environment -Name COMPlus_ETWEnabled -Value 0 -PropertyType String -Force`, dialect: DialectPowerShell, want: true},
		{name: "CMD dotnet ETW", command: `REG ADD HKLM\Software\Microsoft\.NETFramework /v ETWEnabled /t REG_DWORD /d 0`, dialect: DialectCMD, want: true},
		{name: "PowerShell dotnet ETW", command: `New-ItemProperty -Path HKLM:\Software\Microsoft\.NETFramework -Name ETWEnabled -Value 0 -PropertyType DWord -Force`, dialect: DialectPowerShell, want: true},
		{name: "Defender operational channel", command: `reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Defender/Operational" /v Enabled /t REG_DWORD /d 0 /f`, dialect: DialectCMD, want: true},
		{name: "EventLog Application autologger", command: `New-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\WMI\Autologger\EventLog-Application -Name Start -Value 0 -PropertyType DWord -Force`, dialect: DialectPowerShell, want: true},
		{name: "restore telemetry", command: `REG ADD HKCU\Environment /v COMPlus_ETWEnabled /t REG_SZ /d 1 /f`, dialect: DialectCMD},
		{name: "wrong value type", command: `REG ADD HKCU\Environment /v COMPlus_ETWEnabled /t REG_DWORD /d 0 /f`, dialect: DialectCMD},
		{name: "nearby provider path", command: `reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\EventLog-System" /v Start /t REG_DWORD /d 0 /f`, dialect: DialectCMD},
		{name: "dynamic value", command: `REG ADD HKCU\Environment /v COMPlus_ETWEnabled /t REG_SZ /d %STATE% /f`, dialect: DialectCMD},
		{name: "wrapper", command: `cmd /c "REG ADD HKCU\Environment /v COMPlus_ETWEnabled /t REG_SZ /d 0 /f"`, dialect: DialectCMD},
		{name: "redirect", command: `REG ADD HKCU\Environment /v COMPlus_ETWEnabled /t REG_SZ /d 0 /f >NUL`, dialect: DialectCMD},
		{name: "extra command", command: "REG ADD HKCU\\Environment /v COMPlus_ETWEnabled /t REG_SZ /d 0 /f\nwhoami", dialect: DialectCMD},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "shell", Command: test.command, CWD: `C:\repo`, DialectHint: test.dialect})
			if got := ExactWindowsTelemetryDisable(facts); got != test.want {
				t.Fatalf("proof=%t want=%t parse=%+v facts=%#v", got, test.want, facts.Parse, facts)
			}
		})
	}
}

func TestExactWindowsCredentialProtectionWeakening(t *testing.T) {
	for _, test := range []struct {
		name    string
		command string
		dialect Dialect
		want    bool
	}{
		{name: "WDigest CMD", command: `reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f`, dialect: DialectCMD, want: true},
		{name: "WDigest PowerShell", command: `Set-ItemProperty -Force -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Value '1' -ErrorAction Ignore`, dialect: DialectPowerShell, want: true},
		{name: "LSA PPL CMD", command: `reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL /t REG_DWORD /d 0 /f`, dialect: DialectCMD, want: true},
		{name: "CMD auto logon pair", command: "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v AutoAdminLogon /t REG_DWORD /d 1 /f\nreg add \"HKLM\\Software\\Policies\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v DefaultPassword /t REG_SZ /d password1 /f", dialect: DialectCMD, want: true},
		{name: "PowerShell auto logon pair", command: "New-ItemProperty \"HKLM:\\Software\\Policies\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" -Name AutoAdminLogon -PropertyType DWord -Value 1 -Force\nNew-ItemProperty \"HKLM:\\Software\\Policies\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" -Name DefaultPassword -Value password1 -Force", dialect: DialectPowerShell, want: true},
		{name: "restore WDigest", command: `reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 0 /f`, dialect: DialectCMD},
		{name: "enable LSA PPL", command: `reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL /t REG_DWORD /d 1 /f`, dialect: DialectCMD},
		{name: "auto logon only", command: `reg add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 1 /f`, dialect: DialectCMD},
		{name: "password only", command: `reg add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword /t REG_SZ /d password1 /f`, dialect: DialectCMD},
		{name: "dynamic password", command: "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v AutoAdminLogon /t REG_DWORD /d 1 /f\nreg add \"HKLM\\Software\\Policies\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v DefaultPassword /t REG_SZ /d %PASSWORD% /f", dialect: DialectCMD},
		{name: "different Winlogon path", command: "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v AutoAdminLogon /t REG_DWORD /d 1 /f\nreg add \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v DefaultPassword /t REG_SZ /d password1 /f", dialect: DialectCMD},
		{name: "extra command", command: "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v AutoAdminLogon /t REG_DWORD /d 1 /f\nreg add \"HKLM\\Software\\Policies\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v DefaultPassword /t REG_SZ /d password1 /f\nwhoami", dialect: DialectCMD},
		{name: "wrapped WDigest", command: `cmd /c "reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f"`, dialect: DialectCMD},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "shell", Command: test.command, CWD: `C:\repo`, DialectHint: test.dialect})
			if got := ExactWindowsCredentialProtectionWeakening(facts); got != test.want {
				t.Fatalf("proof=%t want=%t parse=%+v facts=%#v", got, test.want, facts.Parse, facts)
			}
		})
	}
}

func TestExactWindowsAMSIDisable(t *testing.T) {
	for _, test := range []struct {
		name    string
		command string
		want    bool
	}{
		{name: "Windows Script setting", command: `New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows Script\Settings" -Name "AmsiEnable" -Value 0 -PropertyType DWORD -Force`, want: true},
		{name: "reflection bypass", command: exactPowerShellAMSIReflection, want: true},
		{name: "provider removal", command: `Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFE}" -Recurse`, want: true},
		{name: "restore Windows Script setting", command: `New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows Script\Settings" -Name "AmsiEnable" -Value 1 -PropertyType DWORD -Force`},
		{name: "different reflection field", command: `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiContext','NonPublic,Static').SetValue($null,$true)`},
		{name: "reflection false", command: `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$false)`},
		{name: "provider root", command: `Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\AMSI\Providers" -Recurse`},
		{name: "provider wildcard", command: `Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\*" -Recurse`},
		{name: "malformed provider GUID", command: `Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\{not-a-guid}" -Recurse`},
		{name: "provider without recurse", command: `Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFE}"`},
		{name: "conditional provider removal", command: `if ($disable) { Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFE}" -Recurse }`},
		{name: "pipeline is not an atomic proof", command: `New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows Script\Settings" -Name "AmsiEnable" -Value 0 -PropertyType DWORD -Force | Out-Null`},
		{name: "extra command", command: exactPowerShellAMSIReflection + "\nWrite-Host done"},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "shell", Command: test.command, CWD: `C:\repo`, DialectHint: DialectPowerShell})
			if got := ExactWindowsAMSIDisable(facts); got != test.want {
				t.Fatalf("proof=%t want=%t parse=%+v facts=%#v", got, test.want, facts.Parse, facts)
			}
		})
	}
}
