// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import "testing"

// Regression tests for the psparse delta review 5 P1 findings (R5-1..R5-5). The
// parser fix is still inbound; these are the effects-side defense-in-depth
// guards in powershell_fe.go (and the powershell-host seam in extract.go). Each
// reviewer case must come out NOT fully known, with no fabricated known target.

var linuxPS = Options{Flavor: FlavorPOSIX, Home: "/home/u", CWD: "/home/u", Dialect: DialectPowerShell, Env: map[string]string{"HOME": "/home/u"}}

// R5-1: an embedded " in a Start-Process / direct powershell -Command payload is
// dropped by the child, so the static parse can miss a command in the quoted
// span. Both forms are opaque, with no fabricated write.
func TestPSReview5_R51EmbeddedQuote(t *testing.T) {
	for _, c := range []string{
		`Start-Process powershell -ArgumentList '-c','New-Item C:\work\x -Value "a;Remove-Item C:\Windows -Recurse"'`,
		`powershell -c 'New-Item C:\work\x -Value "a;Remove-Item C:\Windows -Recurse"'`,
	} {
		r := Extract(Call{Surface: SurfaceShell, Command: c}, winPS)
		if r.FullyKnown() {
			t.Errorf("R5-1 %q is fully known: %s", c, fmtRes(r))
		}
		if !hasReasonCode(r, ReasonOpaqueCode) {
			t.Errorf("R5-1 %q not opaque: %s", c, fmtRes(r))
		}
		if has(r, KindWrite, `c:\work\x`, TargetStateKnown) && !hasReasonCode(r, ReasonOpaqueCode) {
			t.Errorf("R5-1 %q trusts the quoted-payload write: %s", c, fmtRes(r))
		}
		if has(r, KindDelete, `c:\windows`, TargetStateKnown) {
			t.Errorf("R5-1 %q leaked a known delete: %s", c, fmtRes(r))
		}
	}
}

// R5-2: a string -ArgumentList keeps its quotes in the nested text; the child
// runs it. Opaque, no fabricated known effect.
func TestPSReview5_R52StringArgumentList(t *testing.T) {
	r := Extract(Call{Surface: SurfaceShell, Command: `Start-Process powershell -ArgumentList '-c "Remove-Item C:\Windows -Recurse"'`}, winPS)
	if r.FullyKnown() || !hasReasonCode(r, ReasonOpaqueCode) {
		t.Fatalf("R5-2 not opaque: %s", fmtRes(r))
	}
	if has(r, KindDelete, `c:\windows`, TargetStateKnown) {
		t.Fatalf("R5-2 leaked a known delete: %s", fmtRes(r))
	}
}

// R5-3: PowerShell expands * ? [ ] inside quotes too, on every platform, so a
// wildcard path argument is never a KNOWN literal target.
func TestPSReview5_R53QuotedWildcards(t *testing.T) {
	cases := []struct {
		c    string
		kind Kind
	}{
		{`Remove-Item '/etc/pass[w]d'`, KindDelete},
		{`Remove-Item "/home/u/.ss?" -Recurse`, KindDelete},
		{`Remove-Item "/home/u/.ss[h]" -Recurse`, KindDelete},
		{`Copy-Item /tmp/x "/home/u/.ssh/authorized_key?"`, KindWrite},
	}
	for _, tc := range cases {
		r := Extract(Call{Surface: SurfaceShell, Command: tc.c}, linuxPS)
		if r.FullyKnown() {
			t.Errorf("R5-3 %q fully known: %s", tc.c, fmtRes(r))
		}
		// the wildcard target must never be a known literal path.
		for _, e := range r.Effects {
			if e.Kind == tc.kind && e.Target.Type == TargetPath && e.TargetState == TargetStateKnown && e.Target.Path != "" {
				t.Errorf("R5-3 %q resolved a wildcard to a known literal %q: %s", tc.c, e.Target.Path, fmtRes(r))
			}
		}
	}
}

// R5-4: Start-Process parameter prefixes (-a / -Arg for -ArgumentList) still
// launch the child; the shell target makes it opaque.
func TestPSReview5_R54ArgPrefix(t *testing.T) {
	for _, c := range []string{
		`Start-Process powershell -a '-c','Remove-Item C:\Windows -Recurse'`,
		`Start-Process powershell -Arg '-c','Remove-Item C:\Windows -Recurse'`,
		`Start-Process cmd -a '/c','del C:\Windows\x'`,
	} {
		r := Extract(Call{Surface: SurfaceShell, Command: c}, winPS)
		if r.FullyKnown() || !hasReasonCode(r, ReasonOpaqueCode) {
			t.Errorf("R5-4 %q not opaque: %s", c, fmtRes(r))
		}
	}
}

// R5-5: a dynamic element before /c (or a list with no /c) must not drop the cmd
// payload; the shell Start-Process is opaque.
func TestPSReview5_R55DynamicBeforeC(t *testing.T) {
	r := Extract(Call{Surface: SurfaceShell, Command: `Start-Process cmd -ArgumentList $a,'rd /s /q C:\Windows'`}, winPS)
	if r.FullyKnown() || !hasReasonCode(r, ReasonOpaqueCode) {
		t.Fatalf("R5-5 not opaque: %s", fmtRes(r))
	}
	if has(r, KindDelete, `c:\windows`, TargetStateKnown) {
		t.Fatalf("R5-5 leaked a known delete: %s", fmtRes(r))
	}
}
