// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

func TestExactWindowsRecoveryDisablePair(t *testing.T) {
	for _, test := range []struct {
		name    string
		command string
		want    bool
	}{
		{
			name: "atomic pair",
			command: "bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures\n" +
				"bcdedit.exe /set {default} recoveryenabled no",
			want: true,
		},
		{
			name: "restoration pair",
			command: "bcdedit.exe /set {default} bootstatuspolicy DisplayAllFailures\n" +
				"bcdedit.exe /set {default} recoveryenabled yes",
		},
		{name: "single setting", command: `bcdedit /set {default} recoveryenabled no`},
		{
			name: "different identifiers",
			command: "bcdedit /set {default} bootstatuspolicy ignoreallfailures\n" +
				"bcdedit /set {current} recoveryenabled no",
		},
		{
			name: "duplicate key",
			command: "bcdedit /set {default} recoveryenabled no\n" +
				"bcdedit /set {default} recoveryenabled no",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "shell", Command: test.command, CWD: `C:\repo`, DialectHint: DialectCMD})
			if got := ExactWindowsRecoveryDisablePair(facts); got != test.want {
				t.Fatalf("proof=%t want=%t facts=%#v", got, test.want, facts)
			}
		})
	}
}

func TestExactWindowsAuditPolicyWipePair(t *testing.T) {
	for _, test := range []struct {
		name    string
		command string
		want    bool
	}{
		{name: "atomic pair", command: "auditpol /clear /y\nauditpol /remove /allusers", want: true},
		{name: "reverse order", command: "auditpol.exe /remove /allusers\nauditpol.exe /clear /y", want: true},
		{name: "single clear", command: `auditpol /clear /y`},
		{name: "clear without consent", command: `auditpol /clear`},
		{name: "restoration", command: `auditpol /set /category:"Account Logon" /success:enable /failure:enable`},
		{name: "duplicate clear", command: "auditpol /clear /y\nauditpol /clear /y"},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "shell", Command: test.command, CWD: `C:\repo`, DialectHint: DialectCMD})
			if got := ExactWindowsAuditPolicyWipePair(facts); got != test.want {
				t.Fatalf("proof=%t want=%t facts=%#v", got, test.want, facts)
			}
		})
	}
}

func TestExactWindowsRecoveryStoreDestruction(t *testing.T) {
	for _, test := range []struct {
		name    string
		command string
		want    bool
	}{
		{name: "delete all system-state versions", command: `wbadmin delete systemstatebackup -keepVersions:0`, want: true},
		{name: "quiet catalog delete", command: `wbadmin.exe delete catalog -quiet`, want: true},
		{name: "delete all shadow copies through WMIC", command: `wmic.exe shadowcopy delete`, want: true},
		{name: "retain one version", command: `wbadmin delete systemstatebackup -keepVersions:1`},
		{name: "interactive catalog delete", command: `wbadmin delete catalog`},
		{name: "backup status", command: `wbadmin get status`},
		{name: "backup creation", command: `wbadmin start backup -backupTarget:D:`},
		{name: "shadow inventory", command: `wmic shadowcopy list brief`},
		{name: "shadow creation", command: `wmic shadowcopy call create Volume=C:\\`},
		{name: "conditional destruction", command: `if exist C:\\flag wmic shadowcopy delete`},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "shell", Command: test.command, CWD: `C:\repo`, DialectHint: DialectCMD})
			if got := ExactWindowsRecoveryStoreDestruction(facts); got != test.want {
				t.Fatalf("proof=%t want=%t facts=%#v", got, test.want, facts)
			}
		})
	}
}

func TestExactWindowsRegistrySecurityControlDisable(t *testing.T) {
	defenderReg := "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\" /v DisableAntiSpyware /t REG_DWORD /d 1 /f >NUL\n" +
		"reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\" /v DisableAntiVirus /t REG_DWORD /d 1 /f >NUL\n" +
		"reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableBehaviorMonitoring /t REG_DWORD /d 1 /f >NUL"
	defenderPowerShell := "Set-ItemProperty -Path 'HKLM:\\Software\\Policies\\Microsoft\\Windows Defender' -Name DisableAntiSpyware -Value 1\n" +
		"Set-ItemProperty -Path 'HKLM:\\Software\\Policies\\Microsoft\\Windows Defender' -Name DisableAntiVirus -Value 1\n" +
		"Set-ItemProperty -Path 'HKLM:\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection' -Name DisableBehaviorMonitoring -Value 1"
	for _, test := range []struct {
		name    string
		command string
		dialect Dialect
		want    bool
	}{
		{name: "disable public firewall profile", command: `reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /v EnableFirewall /t REG_DWORD /d 0 /f`, dialect: DialectCMD, want: true},
		{name: "disable domain firewall profile", command: `reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v EnableFirewall /t REG_DWORD /d 0 /f`, dialect: DialectCMD, want: true},
		{name: "disable uac", command: `reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f`, dialect: DialectCMD, want: true},
		{name: "disable uac admin prompt", command: `reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 0 /f`, dialect: DialectCMD, want: true},
		{name: "disable hvci", command: `reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d 0 /f`, dialect: DialectCMD, want: true},
		{name: "disable tamper protection", command: `reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v "TamperProtection" /t REG_DWORD /d 0 /f`, dialect: DialectCMD, want: true},
		{name: "allow vulnerable credssp oracle", command: `reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" /v AllowEncryptionOracle /t REG_DWORD /d 2 /f`, dialect: DialectCMD, want: true},
		{name: "disable rdp security layer", command: `reg add "hklm\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`, dialect: DialectCMD, want: true},
		{name: "disable rdp nla", command: `reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /d 0 /t REG_DWORD /f`, dialect: DialectCMD, want: true},
		{name: "three defender registry controls", command: defenderReg, dialect: DialectCMD, want: true},
		{name: "three defender powershell controls", command: defenderPowerShell, dialect: DialectPowerShell, want: true},
		{name: "restore firewall", command: `reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v EnableFirewall /t REG_DWORD /d 1 /f`, dialect: DialectCMD},
		{name: "single defender control", command: `reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f`, dialect: DialectCMD},
		{name: "duplicate defender control", command: "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\" /v DisableAntiSpyware /t REG_DWORD /d 1 /f\nreg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\" /v DisableAntiSpyware /t REG_DWORD /d 1 /f\nreg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\" /v DisableAntiSpyware /t REG_DWORD /d 1 /f", dialect: DialectCMD},
		{name: "dynamic firewall value", command: `reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v EnableFirewall /t REG_DWORD /d %STATE% /f`, dialect: DialectCMD},
		{name: "unrelated registry DWORD", command: `reg add "HKLM\SOFTWARE\Acme" /v EnableFirewall /t REG_DWORD /d 0 /f`, dialect: DialectCMD},
		{name: "ordinary explorer setting", command: `reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f`, dialect: DialectCMD},
		{name: "rdp enablement alone", command: `reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f`, dialect: DialectCMD},
		{name: "uac restoration", command: `reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f`, dialect: DialectCMD},
		{name: "uac admin prompt restoration", command: `reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 5 /f`, dialect: DialectCMD},
		{name: "wrong uac path", command: `reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f`, dialect: DialectCMD},
		{name: "wrong hvci value name", command: `reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v AuditMode /t REG_DWORD /d 0 /f`, dialect: DialectCMD},
		{name: "tamper protection alternate data", command: `reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v TamperProtection /t REG_DWORD /d 4 /f`, dialect: DialectCMD},
		{name: "credssp alternate data", command: `reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" /v AllowEncryptionOracle /t REG_DWORD /d 1 /f`, dialect: DialectCMD},
		{name: "rdp tls security layer", command: `reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 2 /f`, dialect: DialectCMD},
		{name: "rdp nla enabled", command: `reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f`, dialect: DialectCMD},
		{name: "registry read", command: `reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA`, dialect: DialectCMD},
		{name: "registry delete", command: `reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /f`, dialect: DialectCMD},
		{name: "dynamic uac data", command: `reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d %VALUE% /f`, dialect: DialectCMD},
		{name: "placeholder uac path", command: `reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\#{system}" /v EnableLUA /t REG_DWORD /d 0 /f`, dialect: DialectCMD},
		{name: "malformed uac path", command: `reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\\Other" /v EnableLUA /t REG_DWORD /d 0 /f`, dialect: DialectCMD},
		{name: "wrong registry type", command: `reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_SZ /d 0 /f`, dialect: DialectCMD},
		{name: "missing force", command: `reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0`, dialect: DialectCMD},
		{name: "extra option", command: `reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f /reg:64`, dialect: DialectCMD},
		{name: "extra command", command: "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v EnableLUA /t REG_DWORD /d 0 /f\nwhoami", dialect: DialectCMD},
		{name: "conditional write", command: `if exist C:\flag reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f`, dialect: DialectCMD},
		{name: "pipeline write", command: `echo y | reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f`, dialect: DialectCMD},
		{name: "powershell set item property", command: `Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -Value 0 -Type DWord`, dialect: DialectPowerShell},
		{name: "powershell dynamic value", command: `Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -Value $value -Type DWord`, dialect: DialectPowerShell},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "shell", Command: test.command, CWD: `C:\repo`, DialectHint: test.dialect})
			if got := ExactWindowsRegistrySecurityControlDisable(facts); got != test.want {
				t.Fatalf("proof=%t want=%t facts=%#v", got, test.want, facts)
			}
		})
	}
}

func TestExactWindowsDefenderMultiControlDisable(t *testing.T) {
	for _, test := range []struct {
		name    string
		command string
		want    bool
	}{
		{
			name: "full names",
			command: "Set-MpPreference -DisableRealtimeMonitoring 1\n" +
				"Set-MpPreference -DisableBehaviorMonitoring 1\n" +
				"Set-MpPreference -DisableScriptScanning 1\n" +
				"Set-MpPreference -DisableBlockAtFirstSeen 1",
			want: true,
		},
		{
			name: "aliases",
			command: "Set-MpPreference -drtm $True\n" +
				"Set-MpPreference -dbm $True\n" +
				"Set-MpPreference -dscrptsc $True\n" +
				"Set-MpPreference -dbaf $True",
			want: true,
		},
		{
			name: "restoration",
			command: "Set-MpPreference -drtm $False\n" +
				"Set-MpPreference -dbm $False\n" +
				"Set-MpPreference -dscrptsc $False",
		},
		{
			name: "only two controls",
			command: "Set-MpPreference -drtm $True\n" +
				"Set-MpPreference -dbm $True",
		},
		{
			name: "duplicate control",
			command: "Set-MpPreference -drtm $True\n" +
				"Set-MpPreference -drtm 1\n" +
				"Set-MpPreference -drtm true",
		},
		{
			name: "dynamic value",
			command: "Set-MpPreference -drtm $disable\n" +
				"Set-MpPreference -dbm $disable\n" +
				"Set-MpPreference -dscrptsc $disable",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "shell", Command: test.command, CWD: `C:\repo`, DialectHint: DialectPowerShell})
			if got := ExactWindowsDefenderMultiControlDisable(facts); got != test.want {
				t.Fatalf("proof=%t want=%t facts=%#v", got, test.want, facts)
			}
		})
	}
}
