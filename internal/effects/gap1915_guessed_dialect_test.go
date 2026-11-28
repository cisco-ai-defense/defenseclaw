// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"encoding/base64"
	"strings"
	"testing"
	"unicode/utf16"
)

// gap1915SQ quotes s for a POSIX shell: one single-quoted word, each ' as '\”.
func gap1915SQ(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// gap1915Encoded is a powershell -EncodedCommand call of script (UTF-16LE,
// base64) with a tab every 12 characters, as the encoded-tabs variant sends it.
func gap1915Encoded(script string) string {
	u := utf16.Encode([]rune(script))
	b := make([]byte, 0, 2*len(u))
	for _, r := range u {
		b = append(b, byte(r), byte(r>>8))
	}
	enc := base64.StdEncoding.EncodeToString(b)
	var parts []string
	for len(enc) > 12 {
		parts = append(parts, enc[:12])
		enc = enc[12:]
	}
	return `powershell -NoProfile -EncodedCommand "` + strings.Join(append(parts, enc), "\t") + `"`
}

// gap1915Cases are the GAP-1915 shapes (DET111 r1 variants of corpus rows): a
// POSIX command on a Windows host with no dialect hint, which the extractor
// guesses as PowerShell, and an encoded PowerShell script whose output stream
// is redirected twice. Each must keep the known mutation of the protected
// target the psparse frontend gave on T21a.
func gap1915Cases() []struct {
	name, cmd string
	kind      Kind
	path      string
	fullyRead bool
} {
	const cfg, audit, keys = `C:\Users\alice\.defenseclaw\config.yaml`, `C:\Users\alice\.defenseclaw\audit.db`, `C:\Users\alice\.ssh\authorized_keys`
	echo := `powershell.exe -NoProfile -Command ` + gap1915SQ(`echo x >> `+cfg)
	outFile := `powershell.exe -NoProfile -Command ` + gap1915SQ(gap1915SQ(`x`)+` | Out-File -FilePath `+audit+` -Append`)
	return []struct {
		name, cmd string
		kind      Kind
		path      string
		fullyRead bool
	}{
		{"find-exec redirection", `find . -maxdepth 0 -exec sh -c ` + gap1915SQ(echo) + ` \;`, KindAppend, cfg, true},
		{"find-exec Out-File -Append", `find . -maxdepth 0 -exec sh -c ` + gap1915SQ(outFile) + ` \;`, KindWrite, audit, false},
		{"dot-stdin redirection", `. /dev/stdin <<< ` + gap1915SQ(echo), KindAppend, cfg, true},
		{"dot-stdin Out-File -Append", `. /dev/stdin <<< ` + gap1915SQ(outFile), KindWrite, audit, false},
		{"encoded 1>&2 then >>", gap1915Encoded(`powershell -Command 'echo ssh-ed25519 AAAA k' 1>&2 >> ` + keys), KindAppend, keys, false},
	}
}

func gap1915Options() Options {
	const home = `C:\Users\alice`
	return Options{Flavor: FlavorWindows, Home: home, CWD: home + `\proj`, Account: AccountRecord{Home: home},
		Env: map[string]string{"USERPROFILE": home}}
}

func gap1915Has(r Result, kind Kind, path string) bool {
	for _, e := range r.Effects {
		if e.Kind == kind && e.Target.Path == path && e.TargetState == TargetStateKnown && e.RoleState == RoleStateKnown {
			return true
		}
	}
	return false
}

// TestGAP1915GuessedDialectKeepsTheKnownMutation: red at c953fc9fe2 (the
// parser port reads '\” as PowerShell quoting and drops a rejected
// redirection), green with the POSIX reading of a guessed dialect and the
// rejected redirection kept.
func TestGAP1915GuessedDialectKeepsTheKnownMutation(t *testing.T) {
	for _, c := range gap1915Cases() {
		r := Extract(Call{Surface: SurfaceShell, Tool: "shell", Command: c.cmd}, gap1915Options())
		if !gap1915Has(r, c.kind, c.path) {
			t.Errorf("%s: no known %s of %s in %+v", c.name, c.kind, c.path, r.Effects)
		}
		if c.fullyRead && len(r.Unknowns) != 0 {
			t.Errorf("%s: structure unknowns %v: a PowerShell parse error runs nothing, the POSIX reading is the call", c.name, r.Unknowns)
		}
	}
}

// TestGAP1915UnionOnlyForAGuessedDialectAndPOSIXSyntax: an explicit dialect is
// read as given, and a guessed PowerShell call with no POSIX-only syntax is
// the PowerShell reading alone.
func TestGAP1915UnionOnlyForAGuessedDialectAndPOSIXSyntax(t *testing.T) {
	o := gap1915Options()
	o.Dialect = DialectPowerShell
	c := gap1915Cases()[0]
	if r := Extract(Call{Surface: SurfaceShell, Tool: "shell", Command: c.cmd}, o); gap1915Has(r, c.kind, c.path) {
		t.Errorf("explicit PowerShell: the POSIX reading was added: %+v", r.Effects)
	}
	for _, cmd := range []string{
		`Write-Output 'it''s' >> C:\Users\alice\proj\notes.txt; Get-Content -Path C:\Users\alice\proj\notes.txt`,
		`powershell -NoProfile -Command "Set-Content -Path C:\Users\alice\proj\x.txt -Value 'a b'"`,
	} {
		guessed := Extract(Call{Surface: SurfaceShell, Tool: "shell", Command: cmd}, gap1915Options())
		given := Extract(Call{Surface: SurfaceShell, Tool: "shell", Command: cmd}, o)
		if len(guessed.Effects) != len(given.Effects) || len(guessed.Unknowns) != len(given.Unknowns) {
			t.Errorf("%q: guessed %+v / %v, want the PowerShell reading %+v / %v", cmd, guessed.Effects, guessed.Unknowns, given.Effects, given.Unknowns)
		}
	}
}
