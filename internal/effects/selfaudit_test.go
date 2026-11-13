// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import "testing"

// TestSelfAuditKnownPathsAreCanonical asserts that no effect carries a KNOWN
// path whose spelling is non-canonical for its flavor (review round 3 self-
// audit): a non-canonical spelling must always be unknown with a reason, never
// a different KNOWN key. Runs over the probe inputs embedded here plus the
// adversarial spelling shapes the reviews found.
func TestSelfAuditKnownPathsAreCanonical(t *testing.T) {
	type tc struct {
		o   Options
		cmd string
	}
	cases := []tc{
		{winCmd, `echo k >> C:\Users\u\.ssh\AUTHOR~1`},
		{winCmd, `del \\.\C:\Windows\x`},
		{winCmd, `del \\localhost\C$\Windows\x`},
		{winCmd, `del \\127.0.0.1\C$\Windows\x`},
		{winPS, `Set-Content -Path 'FileSystem::C:\Users\u\.ssh\authorized_keys' -Value k`},
		{winPS, `Add-Content Env:\PATH k`},
		{envOpts, `echo x > $'/home/u/.bash\x72c'`},
		{winCmd, `echo k >> %USERPROFILE2%\authorized_keys`},
	}
	for _, c := range cases {
		r := Extract(Call{Surface: SurfaceShell, Command: c.cmd}, c.o)
		for i, e := range r.Effects {
			if e.TargetState != TargetStateKnown || e.Target.Type != TargetPath {
				continue
			}
			spell := e.Target.Spelling
			if spell == "" {
				spell = e.Target.Path
			}
			if canonicalIssue(spell, e.Target.Flavor) != "" {
				t.Errorf("KNOWN non-canonical path effect %d for %q: spelling=%q path=%q", i, c.cmd, e.Target.Spelling, e.Target.Path)
			}
		}
	}
}

// TestSelfAuditUnlistedFlagIsNotFullyKnown asserts that a command carrying a
// flag not in its table entry is never reported fully known (the allowlist
// rule): the operand effects must carry an unknown_flag reason.
func TestSelfAuditUnlistedFlagIsNotFullyKnown(t *testing.T) {
	cases := []string{
		`cp --totally-bogus-flag a.txt b.txt`,
		`rm --made-up /tmp/x`,
		`grep --no-such-flag x /home/u/.netrc`,
	}
	for _, cmd := range cases {
		r := Extract(Call{Surface: SurfaceShell, Command: cmd}, envOpts)
		if r.FullyKnown() {
			t.Errorf("command with an unlisted flag is fully known: %q", cmd)
		}
	}
}
