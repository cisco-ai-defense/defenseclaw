// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookexec

import (
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// GAP-0167: the budgets of a hook launched through the system PowerShell
// bridge (Codex) or the per-user stable launcher count from the wrapper's
// start; anything else keeps the hook's own start.
func TestCallStartCountsTheWrappersThatLaunchedTheHook(t *testing.T) {
	const powerShell = `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
	created := time.Unix(1_000, 0)
	at := func(lead time.Duration) time.Time { return created.Add(-lead) }
	for _, test := range []struct {
		name  string
		chain []hookWrapperProcess
		want  time.Time
	}{
		{"no parent", nil, created},
		{"the agent itself", []hookWrapperProcess{{`C:\Users\u\AppData\Local\claude\claude.exe`, at(time.Hour)}}, created},
		{"system PowerShell bridge", []hookWrapperProcess{{powerShell, at(1900 * time.Millisecond)}}, at(1900 * time.Millisecond)},
		{"PowerShell, case differs", []hookWrapperProcess{{`c:\windows\system32\windowspowershell\v1.0\POWERSHELL.EXE`, at(time.Second)}}, at(time.Second)},
		{"another PowerShell", []hookWrapperProcess{{`C:\Program Files\PowerShell\7\pwsh.exe`, at(time.Second)}}, created},
		{"PowerShell started long before (a shell)", []hookWrapperProcess{{powerShell, at(time.Minute)}}, created},
		{"reused process id", []hookWrapperProcess{{powerShell, created.Add(time.Second)}}, created},
		{"bridge then stable launcher", []hookWrapperProcess{
			{`C:\Users\u\.local\bin\defenseclaw-hook.exe`, at(800 * time.Millisecond)},
			{powerShell, at(1500 * time.Millisecond)},
		}, at(1500 * time.Millisecond)},
		// GAP-1908: the direct Codex registration starts the launcher through
		// the system cmd.exe, as the per-user Claude Code command does; like
		// the agent's own shell it is not a wrapper the budgets count.
		{"system cmd.exe of a direct registration", []hookWrapperProcess{{`C:\Windows\System32\cmd.exe`, at(300 * time.Millisecond)}}, created},
		{"launcher under the agent", []hookWrapperProcess{
			{`C:\Users\u\.local\bin\defenseclaw-hook.exe`, at(800 * time.Millisecond)},
			{`C:\Users\u\AppData\Local\claude\claude.exe`, at(time.Hour)},
		}, at(800 * time.Millisecond)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := callStartBehindWrappers(created, test.chain, powerShell); !got.Equal(test.want) {
				t.Fatalf("call start %s, want %s", got, test.want)
			}
		})
	}
}

// The live reader never names a start after this process's own creation.
func TestProcessStartTimeIsNoLaterThanThisProcess(t *testing.T) {
	started, ok := processStartTime(time.Now())
	if !ok {
		t.Fatal("no process start on Windows")
	}
	own, err := processCreationTime(windows.CurrentProcess())
	if err != nil {
		t.Fatal(err)
	}
	if started.After(own) {
		t.Fatalf("call start %s is after this process's creation %s", started, own)
	}
}
