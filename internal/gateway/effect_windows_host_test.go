// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/effects"
)

// TestDET111EffectLaneReadsWindowsHostCallsWithWindowsPaths (S3-R1E 03:22Z):
// a call a Windows host runs is read with Windows path rules by the effect
// lane, as the readers read it: a Codex shell the hook placed in no dialect
// is read as PowerShell or cmd (not POSIX, whose lexer ate the backslashes
// of C:\Users\...), and Git Bash (hint POSIX, or Claude Code's Bash tool)
// keeps the POSIX grammar with Windows paths. At 61904b1afb the lane read
// all of them with POSIX paths, so none wrote the keys file.
func TestDET111EffectLaneReadsWindowsHostCallsWithWindowsPaths(t *testing.T) {
	const home = `C:\Users\alice`
	const keys = `C:\Users\alice\.ssh\authorized_keys`
	cases := []struct {
		name      string
		connector string
		in        actionfacts.Input
		windows   bool // the Windows hook placed it
		dialect   effects.Dialect
	}{
		{"codex shell, no hint, Windows hook", "codex",
			actionfacts.Input{Tool: "shell", Command: `Add-Content -Path C:\Users\alice\.ssh\authorized_keys -Value k`}, true, effects.DialectNone},
		{"codex shell, no hint, Windows folder", "codex",
			actionfacts.Input{Tool: "shell", Command: `echo k >> C:\Users\alice\.ssh\authorized_keys`}, false, effects.DialectNone},
		{"Git Bash, hint POSIX", "codex",
			actionfacts.Input{Tool: "shell", Command: `echo k >> ~/.ssh/authorized_keys`, DialectHint: actionfacts.DialectPOSIX}, true, effects.DialectPOSIX},
		{"Claude Code Bash, no hint", "claudecode",
			actionfacts.Input{Tool: "Bash", Command: `echo k >> ~/.ssh/authorized_keys`}, true, effects.DialectPOSIX},
	}
	for _, tc := range cases {
		tc.in.ActiveHome, tc.in.CWD = home, home+`\proj`
		request := trustedActionRequest{Input: tc.in, Connector: tc.connector,
			windowsShellDialect: tc.windows, windowsDialectReadings: tc.windows}
		call, opts, ok := effectCall(request.Connector, request.Input, effectWindowsCall(request))
		if !ok {
			t.Fatalf("%s: no call", tc.name)
		}
		if opts.Flavor != effects.FlavorWindows || opts.Dialect != tc.dialect {
			t.Errorf("%s: flavor %s dialect %q, want windows %q", tc.name, opts.Flavor, opts.Dialect, tc.dialect)
		}
		var wrote bool
		for _, e := range effects.Extract(call, opts).Effects {
			if (e.Kind == effects.KindWrite || e.Kind == effects.KindAppend) && strings.EqualFold(e.Target.Path, keys) {
				wrote = true
			}
		}
		if !wrote {
			t.Errorf("%s: no write of %s: %+v", tc.name, keys, effects.Extract(call, opts).Effects)
		}
	}
	// PowerShell expands a bare $env:USERPROFILE\x word from the trusted hook home.
	call, opts, ok := effectCall("claudecode", actionfacts.Input{Tool: "PowerShell", Command: `Set-Content $env:USERPROFILE\x\.aws\credentials k`, ActiveHome: home, DialectHint: actionfacts.DialectPowerShell}, true)
	if !ok || opts.Env["USERPROFILE"] != home {
		t.Fatalf("Windows hook did not supply the trusted USERPROFILE: ok=%v env=%v", ok, opts.Env)
	}
	found := false
	for _, e := range effects.Extract(call, opts).Effects {
		if e.Kind == effects.KindWrite && strings.EqualFold(e.Target.Path, home+`\x\.aws\credentials`) {
			found = true
		}
	}
	if !found {
		t.Fatalf("Windows hook USERPROFILE write did not resolve: %+v", effects.Extract(call, opts).Effects)
	}
	// A POSIX host call keeps POSIX paths.
	request := shadowLiveRequest(`echo k >> ~/.ssh/authorized_keys`)
	if _, opts, _ := effectCall(request.Connector, request.Input, effectWindowsCall(request)); opts.Flavor != effects.FlavorPOSIX {
		t.Errorf("POSIX host call: flavor %s, want posix", opts.Flavor)
	}
}
