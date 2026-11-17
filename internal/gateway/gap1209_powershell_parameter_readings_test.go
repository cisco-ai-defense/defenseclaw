// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"slices"
	"testing"
)

// TestGAP1209AmbiguousValuedParameterIsNeverASwitch pins how
// psParameterReadings reads a parameter its cmdlet does not bind
// (rel-1-0-10:GAP-1209). A word that only parameters taking a value and
// naming no path start (-t of mv: ItemType, Value and ToSession of the
// other mutators) binds, if at all, with the next word as its value, so
// plain, the statement that stands for the form, drops both, and no reading
// keeps that word as a positional: mv -t <folder> <file> moved the folder in
// the PowerShell reading of the hook-config guard and alerted on a file
// moved into the Claude Code settings folder. A word that may be a switch or
// a path (-F of Remove-Item: Force, Filter) or that no parameter starts
// (-Zz) keeps both readings and the form, so the RV15-2 rows keep their
// proof.
func TestGAP1209AmbiguousValuedParameterIsNeverASwitch(t *testing.T) {
	rows := []struct {
		name, form, plain string
		want, never       []string
	}{
		{
			name:  "valued-only prefix takes the next word",
			form:  `mv -t C:\Users\a\.claude notes.txt`,
			plain: `mv notes.txt`,
			never: []string{`mv C:\Users\a\.claude notes.txt`},
		},
		{
			name:  "valued-only prefix before the operands",
			form:  `Move-Item -T x C:\Users\a\notes.txt C:\Users\a\old.txt`,
			plain: `Move-Item C:\Users\a\notes.txt C:\Users\a\old.txt`,
			never: []string{`Move-Item x C:\Users\a\notes.txt C:\Users\a\old.txt`},
		},
		{
			name:  "valued-only prefix next to a resolved one",
			form:  `mv -t C:\Users\a\.claude -Fo notes.txt`,
			plain: `mv -Force notes.txt`,
			never: []string{`mv -t C:\Users\a\.claude -Force notes.txt`},
		},
		{
			name:  "valued-only prefix next to an unknown one",
			form:  `mv -t C:\Users\a\.claude -Zz notes.txt`,
			plain: `mv -Zz notes.txt`,
			want:  []string{`mv notes.txt`, `mv`},
		},
		{
			name:  "valued-only prefix with its value",
			form:  `Remove-Item -T:x C:\Users\a\notes.txt`,
			plain: `Remove-Item C:\Users\a\notes.txt`,
		},
		{
			name: "unknown name keeps both readings",
			form: `Rename-Item C:\Users\a\notes.txt c.bak -Zz 1`,
			want: []string{`Rename-Item C:\Users\a\notes.txt c.bak 1`, `Rename-Item C:\Users\a\notes.txt c.bak`},
		},
		{
			name: "prefix of a switch keeps the switch reading",
			form: `Remove-Item -F C:\Users\a\notes.txt`,
			want: []string{`Remove-Item C:\Users\a\notes.txt`, `Remove-Item`},
		},
		{
			name:  "valued-only prefix as the last word",
			form:  `Remove-Item C:\Users\a\notes.txt -t`,
			plain: `Remove-Item C:\Users\a\notes.txt`,
		},
	}
	for _, row := range rows {
		readings, plain, bounded := psParameterReadings(row.form)
		if bounded {
			t.Fatalf("%s: bounded", row.name)
		}
		if want := row.plain; want == "" && plain != row.form || want != "" && plain != want {
			t.Errorf("%s: plain %q, want %q (form %q)", row.name, plain, row.plain, row.form)
		}
		for _, want := range row.want {
			if !slices.Contains(readings, want) {
				t.Errorf("%s: readings %q lack %q", row.name, readings, want)
			}
		}
		for _, never := range row.never {
			if slices.Contains(readings, never) || plain == never {
				t.Errorf("%s: readings %q or plain %q hold %q", row.name, readings, plain, never)
			}
		}
	}
}

// TestGAP1232ParameterBindsToItsCmdlet pins rel-1-0-10:GAP-1232:
// psParameterReadings binds a prefix against the parameters of the cmdlet
// in the statement, aliases included, as PowerShell does. One that names
// one parameter is that parameter, spelled out, and plain stays the form,
// so the form keeps its proof: -L and -LP are LiteralPath (LP is its
// alias), -Fi is FilePath on Out-File and Tee-Object and Filter on
// Remove-Item, -T is ToSession on Copy-Item and -Ty ItemType on New-Item.
func TestGAP1232ParameterBindsToItsCmdlet(t *testing.T) {
	const file = `C:\Users\a\notes.txt`
	rows := []struct{ form, reading string }{
		{`Remove-Item -L ` + file, `Remove-Item -LiteralPath ` + file},
		{`Remove-Item -LP ` + file, `Remove-Item -LiteralPath ` + file},
		{`Remove-Item -PSP ` + file, `Remove-Item -LiteralPath ` + file},
		{`Remove-Item -L:` + file + ` -Force`, `Remove-Item -LiteralPath ` + file + ` -Force`},
		{`Out-File -Fi ` + file, `Out-File -FilePath ` + file},
		{`Out-File -Fil ` + file + ` -InputObject x`, `Out-File -FilePath ` + file + ` -InputObject x`},
		{`Tee-Object -Fi ` + file, `Tee-Object -FilePath ` + file},
		{`Remove-Item -Fi x ` + file, `Remove-Item -Filter x ` + file},
		{`Copy-Item -T x ` + file + ` b`, `Copy-Item -ToSession x ` + file + ` b`},
		{`New-Item -Ty File ` + file, `New-Item -ItemType File ` + file},
		{`Rename-Item -F ` + file + ` b`, `Rename-Item -Force ` + file + ` b`},
	}
	for _, row := range rows {
		readings, plain, bounded := psParameterReadings(row.form)
		if bounded {
			t.Fatalf("%s: bounded", row.form)
		}
		if plain != row.form {
			t.Errorf("%s: plain %q, want the form", row.form, plain)
		}
		if !slices.Equal(readings, []string{row.reading}) {
			t.Errorf("%s: readings %q, want [%q]", row.form, readings, row.reading)
		}
	}
}
