// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

func TestProvesWindowsUACAutoElevationHijack(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		command string
		want    bool
	}{
		{
			name: "Atomic Event Viewer default payload",
			command: `New-Item "HKCU:\software\classes\mscfile\shell\open\command" -Force
Set-ItemProperty "HKCU:\software\classes\mscfile\shell\open\command" -Name "(default)" -Value "C:\Windows\System32\cmd.exe" -Force
Start-Process "C:\Windows\System32\eventvwr.msc"`,
			want: true,
		},
		{
			name: "Atomic Event Viewer native registry form",
			command: `reg.exe add hkcu\software\classes\mscfile\shell\open\command /ve /d "C:\Windows\System32\cmd.exe" /f
Start-Process -FilePath "C:\Windows\System32\eventvwr.msc"`,
			want: true,
		},
		{
			name: "Atomic Fodhelper concrete default",
			command: `New-Item "HKCU:\software\classes\ms-settings\shell\open\command" -Force
reg.exe add hkcu\software\classes\ms-settings\shell\open\command /v DelegateExecute /f
Set-ItemProperty "HKCU:\software\classes\ms-settings\shell\open\command" -Name "(default)" -Value "C:\Windows\System32\cmd.exe" -Force
Start-Process "C:\Windows\System32\fodhelper.exe"`,
			want: true,
		},
		{
			name: "Fodhelper native registry order",
			command: `reg.exe add HKCU\Software\Classes\ms-settings\shell\open\command /ve /t REG_EXPAND_SZ /d "C:\Windows\System32\cmd.exe /c whoami" /f
reg.exe add HKCU\Software\Classes\ms-settings\shell\open\command /v DelegateExecute /t REG_SZ /f
Start-Process -FilePath C:\Windows\System32\fodhelper.exe`,
			want: true,
		},
		{
			name: "sdclt exact static equivalent",
			command: `reg.exe add HKCU\Software\Classes\Folder\shell\open\command /ve /d "cmd.exe /c notepad.exe" /f
reg.exe add HKCU\Software\Classes\Folder\shell\open\command /v DelegateExecute /f
Start-Process -FilePath C:\Windows\System32\sdclt.exe`,
			want: true,
		},
		{
			name:    "event viewer trigger only",
			command: `Start-Process C:\Windows\System32\eventvwr.msc`,
		},
		{
			name:    "handler only",
			command: `reg.exe add HKCU\Software\Classes\mscfile\shell\open\command /ve /d C:\Windows\System32\cmd.exe /f`,
		},
		{
			name: "event viewer wrong handler",
			command: `reg.exe add HKCU\Software\Classes\ms-settings\shell\open\command /ve /d C:\Windows\System32\cmd.exe /f
Start-Process C:\Windows\System32\eventvwr.msc`,
		},
		{
			name: "fodhelper wrong handler",
			command: `reg.exe add HKCU\Software\Classes\mscfile\shell\open\command /ve /d C:\Windows\System32\cmd.exe /f
Start-Process C:\Windows\System32\fodhelper.exe`,
		},
		{
			name: "sdclt wrong handler",
			command: `reg.exe add HKCU\Software\Classes\ms-settings\shell\open\command /ve /d C:\Windows\System32\cmd.exe /f
reg.exe add HKCU\Software\Classes\ms-settings\shell\open\command /v DelegateExecute /f
Start-Process C:\Windows\System32\sdclt.exe`,
		},
		{
			name: "unrelated HKCU Classes key",
			command: `reg.exe add HKCU\Software\Classes\txtfile\shell\open\command /ve /d C:\Windows\System32\cmd.exe /f
Start-Process C:\Windows\System32\eventvwr.msc`,
		},
		{
			name: "machine Classes key",
			command: `reg.exe add HKLM\Software\Classes\mscfile\shell\open\command /ve /d C:\Windows\System32\cmd.exe /f
Start-Process C:\Windows\System32\eventvwr.msc`,
		},
		{
			name: "Atomic Event Viewer unresolved placeholder",
			command: `reg.exe add hkcu\software\classes\mscfile\shell\open\command /ve /d "#{executable_binary}" /f
Start-Process C:\Windows\System32\eventvwr.msc`,
		},
		{
			name: "Atomic Fodhelper unresolved placeholder",
			command: `reg.exe add hkcu\software\classes\ms-settings\shell\open\command /ve /d "#{executable_binary}" /f
reg.exe add hkcu\software\classes\ms-settings\shell\open\command /v DelegateExecute /f
Start-Process C:\Windows\System32\fodhelper.exe`,
		},
		{
			name: "Atomic sdclt unresolved payload and trigger",
			command: `New-Item -Force -Path "HKCU:\Software\Classes\Folder\shell\open\command" -Value '#{command_to_execute}'
New-ItemProperty -Force -Path "HKCU:\Software\Classes\Folder\shell\open\command" -Name DelegateExecute
Start-Process -FilePath $env:windir\system32\sdclt.exe`,
		},
		{
			name: "dynamic payload",
			command: `reg.exe add HKCU\Software\Classes\mscfile\shell\open\command /ve /d $env:ComSpec /f
Start-Process C:\Windows\System32\eventvwr.msc`,
		},
		{
			name: "CMD expansion payload",
			command: `reg.exe add HKCU\Software\Classes\mscfile\shell\open\command /ve /d %COMSPEC% /f
Start-Process C:\Windows\System32\eventvwr.msc`,
		},
		{
			name: "dynamic trigger path",
			command: `reg.exe add HKCU\Software\Classes\Folder\shell\open\command /ve /d "cmd.exe /c notepad.exe" /f
reg.exe add HKCU\Software\Classes\Folder\shell\open\command /v DelegateExecute /f
Start-Process -FilePath $env:windir\system32\sdclt.exe`,
		},
		{
			name: "bare trigger is unresolved",
			command: `reg.exe add HKCU\Software\Classes\mscfile\shell\open\command /ve /d C:\Windows\System32\cmd.exe /f
Start-Process eventvwr.msc`,
		},
		{
			name: "lookalike trigger path",
			command: `reg.exe add HKCU\Software\Classes\mscfile\shell\open\command /ve /d C:\Windows\System32\cmd.exe /f
Start-Process C:\repo\Windows\System32\eventvwr.msc`,
		},
		{
			name: "missing DelegateExecute",
			command: `reg.exe add HKCU\Software\Classes\ms-settings\shell\open\command /ve /d C:\Windows\System32\cmd.exe /f
Start-Process C:\Windows\System32\fodhelper.exe`,
		},
		{
			name: "nonempty DelegateExecute",
			command: `reg.exe add HKCU\Software\Classes\ms-settings\shell\open\command /ve /d C:\Windows\System32\cmd.exe /f
reg.exe add HKCU\Software\Classes\ms-settings\shell\open\command /v DelegateExecute /d handler /f
Start-Process C:\Windows\System32\fodhelper.exe`,
		},
		{
			name: "event viewer extraneous DelegateExecute",
			command: `reg.exe add HKCU\Software\Classes\mscfile\shell\open\command /ve /d C:\Windows\System32\cmd.exe /f
reg.exe add HKCU\Software\Classes\mscfile\shell\open\command /v DelegateExecute /f
Start-Process C:\Windows\System32\eventvwr.msc`,
		},
		{
			name: "cleanup after trigger",
			command: `reg.exe add HKCU\Software\Classes\mscfile\shell\open\command /ve /d C:\Windows\System32\cmd.exe /f
Start-Process C:\Windows\System32\eventvwr.msc
Remove-Item HKCU:\Software\Classes\mscfile -Recurse -Force`,
		},
		{
			name: "cleanup before trigger",
			command: `reg.exe add HKCU\Software\Classes\mscfile\shell\open\command /ve /d C:\Windows\System32\cmd.exe /f
Remove-Item HKCU:\Software\Classes\mscfile -Recurse -Force
Start-Process C:\Windows\System32\eventvwr.msc`,
		},
		{
			name: "restore empty default",
			command: `reg.exe add HKCU\Software\Classes\mscfile\shell\open\command /ve /d "" /f
Start-Process C:\Windows\System32\eventvwr.msc`,
		},
		{
			name: "trigger precedes mutation",
			command: `Start-Process C:\Windows\System32\eventvwr.msc
reg.exe add HKCU\Software\Classes\mscfile\shell\open\command /ve /d C:\Windows\System32\cmd.exe /f`,
		},
		{
			name: "duplicate default mutation",
			command: `reg.exe add HKCU\Software\Classes\mscfile\shell\open\command /ve /d C:\Windows\System32\cmd.exe /f
reg.exe add HKCU\Software\Classes\mscfile\shell\open\command /ve /d C:\Windows\System32\notepad.exe /f
Start-Process C:\Windows\System32\eventvwr.msc`,
		},
		{
			name: "duplicate DelegateExecute",
			command: `reg.exe add HKCU\Software\Classes\ms-settings\shell\open\command /ve /d C:\Windows\System32\cmd.exe /f
reg.exe add HKCU\Software\Classes\ms-settings\shell\open\command /v DelegateExecute /f
reg.exe add HKCU\Software\Classes\ms-settings\shell\open\command /v DelegateExecute /f
Start-Process C:\Windows\System32\fodhelper.exe`,
		},
		{
			name: "conflicting default selectors",
			command: `reg.exe add HKCU\Software\Classes\mscfile\shell\open\command /ve /v Other /d C:\Windows\System32\cmd.exe /f
Start-Process C:\Windows\System32\eventvwr.msc`,
		},
		{
			name: "missing force",
			command: `reg.exe add HKCU\Software\Classes\mscfile\shell\open\command /ve /d C:\Windows\System32\cmd.exe
Start-Process C:\Windows\System32\eventvwr.msc`,
		},
		{
			name: "non-string handler type",
			command: `reg.exe add HKCU\Software\Classes\mscfile\shell\open\command /ve /t REG_DWORD /d 1 /f
Start-Process C:\Windows\System32\eventvwr.msc`,
		},
		{
			name:    "conditional sequence",
			command: `if ($enabled) { reg.exe add HKCU\Software\Classes\mscfile\shell\open\command /ve /d C:\Windows\System32\cmd.exe /f; Start-Process C:\Windows\System32\eventvwr.msc }`,
		},
		{
			name: "preview trigger",
			command: `reg.exe add HKCU\Software\Classes\mscfile\shell\open\command /ve /d C:\Windows\System32\cmd.exe /f
Start-Process C:\Windows\System32\eventvwr.msc -WhatIf`,
		},
		{
			name: "trigger arguments are not exact",
			command: `reg.exe add HKCU\Software\Classes\mscfile\shell\open\command /ve /d C:\Windows\System32\cmd.exe /f
Start-Process C:\Windows\System32\eventvwr.msc -ArgumentList test`,
		},
		{
			name: "extra unrelated command",
			command: `reg.exe add HKCU\Software\Classes\mscfile\shell\open\command /ve /d C:\Windows\System32\cmd.exe /f
Write-Host ready
Start-Process C:\Windows\System32\eventvwr.msc`,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(Input{
				Tool:        "shell",
				Command:     test.command,
				CWD:         `C:\repo`,
				ActiveHome:  `C:\Users\alice`,
				DialectHint: DialectPowerShell,
			})
			if got := ProvesWindowsUACAutoElevationHijack(facts); got != test.want {
				t.Fatalf("proof=%t want=%t parse=%+v facts=%#v", got, test.want, facts.Parse, facts)
			}
		})
	}
}

func TestProvesWindowsUACAutoElevationHijackRequiresEnforcementAuthority(t *testing.T) {
	facts := Analyze(Input{
		Tool: "shell",
		Command: `reg.exe add HKCU\Software\Classes\mscfile\shell\open\command /ve /d C:\Windows\System32\cmd.exe /f
Start-Process C:\Windows\System32\eventvwr.msc`,
		CWD:         `C:\repo`,
		ActiveHome:  `C:\Users\alice`,
		DialectHint: DialectPowerShell,
	})
	if !ProvesWindowsUACAutoElevationHijack(facts) {
		t.Fatalf("positive setup did not prove UAC hijack: parse=%+v facts=%#v", facts.Parse, facts)
	}

	nonAuthoritative := facts
	nonAuthoritative.Parse.Status = StatusPartial
	if ProvesWindowsUACAutoElevationHijack(nonAuthoritative) {
		t.Fatal("partial facts proved a UAC auto-elevation hijack")
	}

	nonEnforceable := facts
	nonEnforceable.Commands = cloneCommands(facts.Commands)
	nonEnforceable.Commands[1].Effect = EffectPreview
	if ProvesWindowsUACAutoElevationHijack(nonEnforceable) {
		t.Fatal("preview facts proved a UAC auto-elevation hijack")
	}

	wrapped := facts
	wrapped.Commands = cloneCommands(facts.Commands)
	wrapped.Commands[1].Wrappers = []WrapperFact{{Executable: "powershell.exe"}}
	if ProvesWindowsUACAutoElevationHijack(wrapped) {
		t.Fatal("wrapped trigger proved a UAC auto-elevation hijack")
	}
}
