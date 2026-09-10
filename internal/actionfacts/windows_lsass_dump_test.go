// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

func TestExactWindowsLSASSMemoryDump(t *testing.T) {
	for _, test := range []struct {
		name    string
		command string
		want    bool
	}{
		{name: "full dump", command: `procdump.exe -accepteula -ma lsass.exe C:\Temp\lsass.dmp`, want: true},
		{name: "mini dump", command: `procdump -mm lsass C:\Forensics\lsass.dmp`, want: true},
		{name: "ordinary process", command: `procdump.exe -ma explorer.exe C:\Temp\explorer.dmp`},
		{name: "missing dump path", command: `procdump.exe -ma lsass.exe`},
		{name: "relative dump path", command: `procdump.exe -ma lsass.exe lsass.dmp`},
		{name: "wrong extension", command: `procdump.exe -ma lsass.exe C:\Temp\lsass.bin`},
		{name: "dynamic target", command: `procdump.exe -ma $process C:\Temp\process.dmp`},
		{name: "dynamic output", command: `procdump.exe -ma lsass.exe $env:TEMP\lsass.dmp`},
		{name: "conditional", command: `if ($capture) { procdump.exe -ma lsass.exe C:\Temp\lsass.dmp }`},
		{name: "pipeline", command: `procdump.exe -ma lsass.exe C:\Temp\lsass.dmp | Write-Output`},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{
				Tool: "shell", Command: test.command, CWD: `C:\repo`, DialectHint: DialectPowerShell,
			})
			if got := ExactWindowsLSASSMemoryDump(facts); got != test.want {
				t.Fatalf("proof=%t want=%t facts=%#v", got, test.want, facts)
			}
		})
	}
}

func TestExactWindowsLSASSMemoryDumpDetection(t *testing.T) {
	for _, test := range []struct {
		name    string
		command string
		want    bool
	}{
		{name: "comsvcs inline lsass pid", command: `C:\Windows\System32\rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).id $env:TEMP\lsass.dmp full`, want: true},
		{name: "out minidump pipeline", command: `Get-Process lsass | Out-Minidump`, want: true},
		{name: "different comsvcs process", command: `C:\Windows\System32\rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process svchost).id $env:TEMP\svchost.dmp full`},
		{name: "different pipeline process", command: `Get-Process explorer | Out-Minidump`},
		{name: "inert text", command: `Write-Host 'Get-Process lsass | Out-Minidump'`},
		{name: "conditional pipeline", command: `if ($capture) { Get-Process lsass | Out-Minidump }`},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{
				Tool: "shell", Command: test.command, CWD: `C:\repo`, DialectHint: DialectPowerShell,
			})
			if got := ExactWindowsLSASSMemoryDumpDetection(facts); got != test.want {
				t.Fatalf("proof=%t want=%t facts=%#v", got, test.want, facts)
			}
		})
	}
}
