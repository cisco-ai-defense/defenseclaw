// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import "testing"

// TestGAP1941StartProcessChildBacktickQuotedCommandIsRead: red at ad6ab569dd
// (an -ArgumentList string with `" escapes was not a literal, so the child's
// -Command was never read and the PowerShell route found no effect), green
// when the child's command line is its decoded value, as for the plain form.
// Raise-only: the opaque marker of a Start-Process child stays.
func TestGAP1941StartProcessChildBacktickQuotedCommandIsRead(t *testing.T) {
	const p = `C:\Users\alice\proj\o.txt`
	o := gap1915Options()
	o.Dialect = DialectPowerShell
	for _, cmd := range []string{
		"Start-Process pwsh -ArgumentList \"-NoProfile -Command `\"Add-Content " + p + " k`\"\"",
		"Start-Process powershell -ArgumentList \"-Command `\"Add-Content " + p + " k`\"\"",
		"saps pwsh -ArgumentList '-NoProfile','-Command',\"`\"Add-Content " + p + " k`\"\"",
		"Start-Process -FilePath pwsh -ArgumentList \"-c `\"Set-Content -Path " + p + " -Value `$x`\"\"",
	} {
		r := Extract(Call{Surface: SurfaceShell, Tool: "shell", Command: cmd}, o)
		write := false
		for _, e := range r.Effects {
			if (e.Kind == KindWrite || e.Kind == KindAppend) && e.Target.Path == p && e.TargetState == TargetStateKnown {
				write = true
			}
		}
		if !write {
			t.Errorf("%q: the child's write of %s was not read: %+v", cmd, p, r.Effects)
		}
		opaque := false
		for _, u := range r.Unknowns {
			opaque = opaque || u.Code == ReasonOpaqueCode
		}
		if !opaque {
			t.Errorf("%q: the Start-Process child lost its opaque marker: %v", cmd, r.Unknowns)
		}
	}
}

// TestGAP1941OtherEscapesStayUnread: an escape whose decoding differs by
// edition or is not one printable character (`e, `n, a doubled backtick) keeps the child
// unread, as before.
func TestGAP1941OtherEscapesStayUnread(t *testing.T) {
	const p = `C:\Users\alice\proj\o.txt`
	o := gap1915Options()
	o.Dialect = DialectPowerShell
	for _, cmd := range []string{
		"Start-Process pwsh -ArgumentList \"-Command Add-Content " + p + " k`e\"",
		"Start-Process pwsh -ArgumentList \"-Command Add-Content " + p + " k`n\"",
		"Start-Process pwsh -ArgumentList \"-Command Add-Content " + p + " k``\"",
	} {
		r := Extract(Call{Surface: SurfaceShell, Tool: "shell", Command: cmd}, o)
		for _, e := range r.Effects {
			if e.Target.Path == p {
				t.Errorf("%q: read a child line with an unsafe escape: %+v", cmd, e)
			}
		}
	}
}
