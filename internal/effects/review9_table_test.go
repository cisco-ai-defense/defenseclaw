// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import "testing"

// psparse review 9 (R9-3, GAP-0193): psparse owns the reading of a cmd /
// powershell / pwsh host call. The walker unwraps the payload only from a Static
// verdict, using psparse's text; a NotStatic verdict stays opaque, and the
// walker's own /c scan never turns an off-table shape into a known payload.
var rv9cases = []rv7case{
	// off-table cmd shapes: psparse is NotStatic (ps_cmd_argv) -> never fully known
	{"rv9-K01 cmd: a word before /c", raPS, "", `cmd foo /c del C:\Users\u\.ssh\authorized_keys`, rdyn},
	{"rv9-K02 cmd: unknown option before /c", raPS, "", `cmd /t:0a /c del C:\Users\u\.ssh\authorized_keys`, rwAK},
	{"rv9-K03 cmd: padded /c", raPS, "", `cmd '/c ' del C:\Users\u\.ssh\authorized_keys`, rwAK},
	{"rv9-K05 cmd: /r", raPS, "", `cmd /r del C:\Users\u\.ssh\authorized_keys`, rwAK},
	{"rv9-K06 cmd: /k then /c", raPS, "", `cmd /k /c del C:\Users\u\.ssh\authorized_keys`, rwAK},
	{"rv9-K07 cmd: two words before /c", raPS, "", `cmd foo bar /c del C:\Users\u\.ssh\authorized_keys`, rdyn},
	{"rv9-K08 cmd: dynamic option", raPS, "", `cmd $o /c del C:\Users\u\.ssh\authorized_keys`, rdyn},
	// the cmd-run shape psparse returns Static: unwrapped in place with its text
	{"rv9-K04 cmd: /d /c table shape", raPS, "", `cmd /d /c del C:\Users\u\.ssh\authorized_keys`, rwAK},
	{"rv9-K09 cmd: /c table shape", raPS, "", `cmd /c del C:\Users\u\.ssh\authorized_keys`, rwAK},
	// pwsh hosts: -wd runs the text elsewhere, which a nested script cannot record
	{"rv9-W03 pwsh -wd", raLinPS, "", `pwsh -wd ~/.ssh -c 'Remove-Item authorized_keys'`, rdyn},
	{"rv9-W04 pwsh -WorkingDirectory", raLinPS, "", `pwsh -WorkingDirectory ~/.ssh -Command Remove-Item authorized_keys`, rdyn},
	{"rv9-W05 powershell -wd win", raPS, "", `powershell -nop -wd C:\Windows\System32 -c 'Remove-Item drivers -Recurse'`, rdyn},
	{"rv9-W07 pwsh -wd -enc", raLinPS, "", `pwsh -wd ~/.ssh -enc UgBlAG0AbwB2AGUALQBJAHQAZQBtACAAYQB1AHQAaABvAHIAaQB6AGUAZABfAGsAZQB5AHMA`, rdyn},
	// ordinary table shapes keep their place in program order
	{"rv9-G02 pwsh -nop -c in order", raLinPS, "", `Set-Location ~/.ssh; pwsh -nop -c 'Remove-Item authorized_keys'; Set-Location /tmp`, rlAK},
}

func TestReview9Table(t *testing.T) {
	for _, c := range rv9cases {
		checkRow(t, c.id, c.o, Call{Surface: SurfaceShell, Command: c.cmd, Workdir: c.wd}, c.real)
	}
}

// A Static host payload is walked once (the walker's unwrap and psparse's copy
// used to double it) and in place, so a later cd does not move it.
func TestHostPayloadWalkedOnceAndInPlace(t *testing.T) {
	r := Extract(Call{Surface: SurfaceShell, Command: `Set-Location ~/.ssh; pwsh -nop -c 'Remove-Item authorized_keys'; Set-Location /tmp`}, raLinPS)
	n := 0
	for _, e := range r.Effects {
		if e.Kind == KindDelete && e.TargetState == TargetStateKnown && e.Target.Key() == propMarker {
			n++
		}
		if e.Kind == KindDelete && e.TargetState == TargetStateKnown && e.Target.Key() == "/tmp/authorized_keys" {
			t.Errorf("the payload ran after the later Set-Location: %s", fmtRes(r))
		}
	}
	if n != 1 {
		t.Errorf("the payload's delete appears %d times, want 1\n%s", n, fmtRes(r))
	}
}
