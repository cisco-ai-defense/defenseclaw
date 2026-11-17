// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"slices"
	"testing"
)

// TestGAP1209AmbiguousValuedParameterIsNeverASwitch pins how
// psParameterReadings reads a parameter it cannot resolve
// (rel-1-0-10:GAP-1209). A prefix that matches only parameters that take a
// value (-t: Type, Target, ToSession) binds, if at all, with the next word as
// its value, so no reading keeps that word as a positional: mv -t <folder>
// <file> moved the folder in the PowerShell reading of the hook-config guard
// and alerted on a file moved into the Claude Code settings folder. A name
// that may be a switch (-F: Force, Filter, FilePath) or that no known
// parameter starts (-Zz) keeps both readings, so the RV15-2 rows keep their
// proof.
func TestGAP1209AmbiguousValuedParameterIsNeverASwitch(t *testing.T) {
	rows := []struct {
		name, form  string
		want, never []string
	}{
		{
			name:  "valued-only prefix takes the next word",
			form:  `mv -t C:\Users\a\.claude notes.txt`,
			want:  []string{`mv notes.txt`},
			never: []string{`mv C:\Users\a\.claude notes.txt`},
		},
		{
			name:  "valued-only prefix before the operands",
			form:  `Move-Item -T x C:\Users\a\notes.txt C:\Users\a\old.txt`,
			want:  []string{`Move-Item C:\Users\a\notes.txt C:\Users\a\old.txt`},
			never: []string{`Move-Item x C:\Users\a\notes.txt C:\Users\a\old.txt`},
		},
		{
			name: "unknown name keeps both readings",
			form: `Rename-Item C:\Users\a\notes.txt c.bak -Zz 1`,
			want: []string{`Rename-Item C:\Users\a\notes.txt c.bak 1`, `Rename-Item C:\Users\a\notes.txt c.bak`},
		},
		{
			name: "prefix of a switch keeps the switch reading",
			form: `Rename-Item -F C:\Users\a\notes.txt c.bak`,
			want: []string{`Rename-Item C:\Users\a\notes.txt c.bak`, `Rename-Item c.bak`},
		},
		{
			name: "valued-only prefix as the last word",
			form: `Remove-Item C:\Users\a\notes.txt -t`,
			want: []string{`Remove-Item C:\Users\a\notes.txt`},
		},
	}
	for _, row := range rows {
		readings, bounded := psParameterReadings(row.form)
		if bounded {
			t.Fatalf("%s: bounded", row.name)
		}
		for _, want := range row.want {
			if !slices.Contains(readings, want) {
				t.Errorf("%s: readings %q lack %q", row.name, readings, want)
			}
		}
		for _, never := range row.never {
			if slices.Contains(readings, never) {
				t.Errorf("%s: readings %q hold %q", row.name, readings, never)
			}
		}
	}
}
