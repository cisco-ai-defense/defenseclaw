// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"encoding/json"
	"strings"
	"testing"
)

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

// TestSelfAuditPOSIXCanonical adds POSIX non-canonical spellings: a KNOWN path
// must have no .., //, /./ or trailing /. (review N4-6).
func TestSelfAuditPOSIXCanonical(t *testing.T) {
	for _, cmd := range []string{
		`rm /home/u/../etc/passwd`,
		`cat /home/u//.bashrc`,
		`rm /home/u/./.bashrc`,
		`rm ../../etc/passwd`,
		`cat /home/u/.ssh/.`,
	} {
		r := Extract(Call{Surface: SurfaceShell, Command: cmd}, envOpts)
		for i, e := range r.Effects {
			if e.TargetState == TargetStateKnown && e.Target.Type == TargetPath && e.Target.Path != "" {
				if strings.Contains(e.Target.Path, "/../") || strings.Contains(e.Target.Path, "//") ||
					strings.Contains(e.Target.Path, "/./") || strings.HasSuffix(e.Target.Path, "/.") {
					t.Errorf("KNOWN non-canonical POSIX path effect %d for %q: %q", i, cmd, e.Target.Path)
				}
			}
		}
	}
}

// TestSelfAuditMutationUnlistedFlag injects an unlisted flag into known-good
// commands and requires each to stop being fully known (review N4-6).
func TestSelfAuditMutationUnlistedFlag(t *testing.T) {
	// For each dialect, inject an unlisted token into a known-good command and
	// require it to stop being fully known (review R5-4).
	type mc struct {
		o       Options
		mutated string
	}
	cases := []mc{
		// POSIX: long, lone short, combined short, wrapper flag.
		{envOpts, `cp --s7-bogus a.txt dir/`},
		{envOpts, `rm -Q /tmp/x`},
		{envOpts, `rm -rQf /tmp/x`},
		{envOpts, `cat --s7-bogus /home/u/.bashrc`},
		{envOpts, `sudo --s7-bogus rm /etc/x`},
		{envOpts, `env --s7-bogus rm /etc/x`},
		// cmd /X switch.
		{winCmd, `del /S7BOGUS C:\x`},
		{winCmd, `copy /S7BOGUS a b`},
		// PowerShell -Param.
		{winPS, `Remove-Item -S7Bogus C:\x`},
		{winPS, `Set-Content -S7Bogus -Path C:\x -Value y`},
		// launcher: tar unlisted flag.
		{envOpts, `tar --s7-bogus -xzf a.tgz -C /etc`},
	}
	for _, c := range cases {
		r := Extract(Call{Surface: SurfaceShell, Command: c.mutated}, c.o)
		if r.FullyKnown() {
			t.Errorf("mutation kept the command fully known: %q", c.mutated)
		}
	}
	// file-tool: an unexpected argument key.
	fr := Extract(Normalize("x", "write", json.RawMessage(`{"file_path":"/home/u/x","content":"y","s7_bogus_key":1}`)), envOpts)
	if fr.FullyKnown() {
		t.Error("file-tool with an unexpected arg key is fully known")
	}
	// MCP is always role-guessed (never fully known) by construction.
	mr := Extract(Normalize("x", "mcp_tool", json.RawMessage(`{"path":"/home/u/x"}`)), envOpts)
	if mr.FullyKnown() {
		t.Error("MCP effect should never be fully known (role guessed)")
	}
}
