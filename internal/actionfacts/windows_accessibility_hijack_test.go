// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

func TestProvesWindowsAccessibilityFeatureHijack(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name    string
		command string
		dialect Dialect
		want    bool
	}{
		{
			name: "CMD IFEO utilman debugger",
			command: `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" ` +
				`/v Debugger /t REG_SZ /d C:\Windows\System32\cmd.exe /f`,
			dialect: DialectCMD,
			want:    true,
		},
		{
			name: "PowerShell IFEO osk debugger",
			command: `Set-ItemProperty -LiteralPath 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe' ` +
				`-Name Debugger -Value 'C:\Windows\System32\cmd.exe'`,
			dialect: DialectPowerShell,
			want:    true,
		},
		{
			name:    "Atomic sticky keys replacement",
			command: `copy /Y C:\Windows\System32\cmd.exe C:\Windows\System32\sethc.exe`,
			dialect: DialectCMD,
			want:    true,
		},
		{
			name:    "Atomic utilman replacement",
			command: `copy /Y C:\Windows\System32\cmd.exe C:\Windows\System32\utilman.exe`,
			dialect: DialectCMD,
			want:    true,
		},
		{
			name:    "Atomic magnifier replacement",
			command: `copy /Y C:\Windows\System32\cmd.exe C:\Windows\System32\Magnify.exe`,
			dialect: DialectCMD,
			want:    true,
		},
		{
			name:    "Atomic narrator replacement",
			command: `copy /Y C:\Windows\System32\cmd.exe C:\Windows\System32\Narrator.exe`,
			dialect: DialectCMD,
			want:    true,
		},
		{
			name:    "Atomic display switch replacement",
			command: `copy /Y C:\Windows\System32\cmd.exe C:\Windows\System32\DisplaySwitch.exe`,
			dialect: DialectCMD,
			want:    true,
		},
		{
			name:    "Atomic AT broker replacement",
			command: `copy /Y C:\Windows\System32\cmd.exe C:\Windows\System32\AtBroker.exe`,
			dialect: DialectCMD,
			want:    true,
		},
		{
			name:    "backup only",
			command: `copy C:\Windows\System32\utilman.exe C:\Windows\System32\utilman_backup.exe`,
			dialect: DialectCMD,
		},
		{
			name:    "restore from backup",
			command: `copy /Y C:\Windows\System32\utilman_backup.exe C:\Windows\System32\utilman.exe`,
			dialect: DialectCMD,
		},
		{
			name:    "take ownership alone",
			command: `takeown /F C:\Windows\System32\sethc.exe /A`,
			dialect: DialectCMD,
		},
		{
			name:    "ACL change alone",
			command: `icacls C:\Windows\System32\sethc.exe /grant Administrators:F /t`,
			dialect: DialectCMD,
		},
		{
			name:    "trigger only",
			command: `atbroker /start malware_test`,
			dialect: DialectCMD,
		},
		{
			name: "unrelated IFEO executable",
			command: `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" ` +
				`/v Debugger /t REG_SZ /d C:\Windows\System32\cmd.exe /f`,
			dialect: DialectCMD,
		},
		{
			name: "unrelated registry tree",
			command: `reg add "HKLM\Software\Fixture\utilman.exe" ` +
				`/v Debugger /t REG_SZ /d C:\Windows\System32\cmd.exe /f`,
			dialect: DialectCMD,
		},
		{
			name: "legitimate debugger executable",
			command: `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" ` +
				`/v Debugger /t REG_SZ /d C:\Windows\System32\vsjitdebugger.exe /f`,
			dialect: DialectCMD,
		},
		{
			name: "unrelated IFEO value",
			command: `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" ` +
				`/v GlobalFlag /t REG_DWORD /d 512 /f`,
			dialect: DialectCMD,
		},
		{
			name: "Atomic unresolved debugger template",
			command: `New-ItemProperty -Path $registryPath -Name $name ` +
				`-Value $Value -PropertyType STRING -Force`,
			dialect: DialectPowerShell,
		},
		{
			name: "dynamic debugger value",
			command: `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" ` +
				`/v Debugger /t REG_SZ /d %COMSPEC% /f`,
			dialect: DialectCMD,
		},
		{
			name:    "conditional replacement",
			command: `if exist C:\marker copy /Y C:\Windows\System32\cmd.exe C:\Windows\System32\sethc.exe`,
			dialect: DialectCMD,
		},
		{
			name:    "replacement outside System32",
			command: `copy /Y C:\Windows\System32\cmd.exe C:\repo\Windows\System32\utilman.exe`,
			dialect: DialectCMD,
		},
		{
			name:    "Atomic dynamic symlink",
			command: `mklink %windir%\System32\osk.exe %windir%\System32\cmd.exe`,
			dialect: DialectCMD,
		},
		{
			name:    "static mklink is not authoritatively projected",
			command: `mklink C:\Windows\System32\osk.exe C:\Windows\System32\cmd.exe`,
			dialect: DialectCMD,
		},
		{
			name: "PowerShell symbolic link target is not authoritatively projected",
			command: `New-Item -Path C:\Windows\System32\osk.exe -ItemType SymbolicLink ` +
				`-Target C:\Windows\System32\cmd.exe`,
			dialect: DialectPowerShell,
		},
		{
			name:    "extra command invalidates atomic proof",
			command: `copy /Y C:\Windows\System32\cmd.exe C:\Windows\System32\sethc.exe` + "\nwhoami",
			dialect: DialectCMD,
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(Input{
				Tool:        "shell",
				Command:     test.command,
				CWD:         `C:\repo`,
				ActiveHome:  `C:\Users\alice`,
				DialectHint: test.dialect,
			})
			if got := ProvesWindowsAccessibilityFeatureHijack(facts); got != test.want {
				t.Fatalf("proof=%t want=%t parse=%+v facts=%#v", got, test.want, facts.Parse, facts)
			}
		})
	}
}

func TestProvesWindowsAccessibilityFeatureHijackRequiresAuthority(t *testing.T) {
	facts := Analyze(Input{
		Tool:        "shell",
		Command:     `copy /Y C:\Windows\System32\cmd.exe C:\Windows\System32\utilman.exe`,
		CWD:         `C:\repo`,
		ActiveHome:  `C:\Users\alice`,
		DialectHint: DialectCMD,
	})
	if !ProvesWindowsAccessibilityFeatureHijack(facts) {
		t.Fatalf("positive setup did not prove hijack: parse=%+v facts=%#v", facts.Parse, facts)
	}

	nonAuthoritative := facts
	nonAuthoritative.Parse.Status = StatusPartial
	if ProvesWindowsAccessibilityFeatureHijack(nonAuthoritative) {
		t.Fatal("partial facts proved an accessibility hijack")
	}

	nonEnforceable := facts
	nonEnforceable.Commands = append([]CommandFact(nil), facts.Commands...)
	nonEnforceable.Commands[0].Effect = EffectPreview
	if ProvesWindowsAccessibilityFeatureHijack(nonEnforceable) {
		t.Fatal("preview facts proved an accessibility hijack")
	}
}
