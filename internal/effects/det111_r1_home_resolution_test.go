// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
package effects

import (
	"strings"
	"testing"
)

func TestDET111R1PowerShellHomeAndUserProfile(t *testing.T) {
	o := Options{Flavor: FlavorWindows, Dialect: DialectPowerShell, Home: `C:\Users\alice`, CWD: `C:\work`, Drive: "C", CaseInsensitive: true, Env: map[string]string{"USERPROFILE": `C:\Users\alice`}}
	cases := []struct {
		name, command, target string
		state                 TargetState
	}{
		{"automatic home", `Set-Content $HOME\.ssh\authorized_keys k`, `c:\users\alice\.ssh\authorized_keys`, TargetStateKnown},
		{"userprofile fused bareword", `Set-Content $env:USERPROFILE\x\.aws\credentials k`, `c:\users\alice\x\.aws\credentials`, TargetStateKnown},
		{"assigned literal home", `$HOME='C:\tmp'; Set-Content $HOME\.ssh\authorized_keys k`, `c:\tmp\.ssh\authorized_keys`, TargetStateKnown},
		{"assigned dynamic home", `$HOME=$dynamic; Set-Content $HOME\.ssh\authorized_keys k`, `c:\users\alice\.ssh\authorized_keys`, TargetStateUnknown},
		{"Set-Variable literal home", `Set-Variable -Name HOME -Value C:\tmp; Set-Content $HOME\.ssh\authorized_keys k`, `c:\tmp\.ssh\authorized_keys`, TargetStateKnown},
		{"Set-Variable dynamic home", `Set-Variable -Name HOME -Value $dynamic; Set-Content $HOME\.ssh\authorized_keys k`, `c:\users\alice\.ssh\authorized_keys`, TargetStateUnknown},
		{"assigned literal userprofile", `$env:USERPROFILE='C:\tmp'; Set-Content $env:USERPROFILE\x\.aws\credentials k`, `c:\tmp\x\.aws\credentials`, TargetStateKnown},
		{"assigned dynamic userprofile", `$env:USERPROFILE=$dynamic; Set-Content $env:USERPROFILE\x\.aws\credentials k`, `c:\users\alice\x\.aws\credentials`, TargetStateUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := Extract(Call{Surface: SurfaceShell, Command: tc.command}, o)
			if tc.state == TargetStateKnown {
				if !has(r, KindWrite, tc.target, tc.state) {
					t.Fatalf("missing write with state %s at %q: %s", tc.state, tc.target, fmtRes(r))
				}
				return
			}
			for _, e := range r.Effects {
				if e.Kind == KindWrite && e.TargetState == TargetStateUnknown {
					return
				}
			}
			t.Fatalf("missing unknown write: %s", fmtRes(r))
		})
	}
}

func TestDET111R1NewgrpStdinBody(t *testing.T) {
	o := Options{Flavor: FlavorPOSIX, Dialect: DialectPOSIX, Home: "/home/bob", CWD: "/home/bob"}
	r := Extract(Call{Surface: SurfaceShell, Command: "newgrp bob <<'EOF'\nprintf k >> /home/bob/.ssh/authorized_keys\nEOF"}, o)
	if !has(r, KindAppend, "/home/bob/.ssh/authorized_keys", TargetStateKnown) {
		t.Fatalf("newgrp stdin body not read as shell code: %s", fmtRes(r))
	}
}

func TestDET111R1TeeObjectAppendAndContent(t *testing.T) {
	o := Options{Flavor: FlavorWindows, Dialect: DialectPowerShell, Home: `C:\Users\u`, CWD: `C:\work`, Drive: "C", CaseInsensitive: true}
	r := Extract(Call{Surface: SurfaceShell, Command: `Write-Output k | Tee-Object -FilePath C:\Users\u\.ssh\authorized_keys -Append`}, o)
	if !has(r, KindAppend, `c:\users\u\.ssh\authorized_keys`, TargetStateKnown) {
		t.Fatalf("Tee-Object append not recognized: %s", fmtRes(r))
	}
	found := false
	for _, e := range r.Effects {
		if e.Kind == KindAppend && strings.EqualFold(e.Target.Path, `c:\users\u\.ssh\authorized_keys`) && e.Data != nil && e.Data.Text != "" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Tee-Object did not attach piped text as file content: %s", fmtRes(r))
	}
}
