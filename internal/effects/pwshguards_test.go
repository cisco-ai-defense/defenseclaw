// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import "testing"

// Regression tests for the PowerShell defense-in-depth guards added ahead of the
// psparse parser fixes (PSPARSE-DELTA-REVIEW4.md). The cases are the reviewer's
// (R4-2 comma lists, R4-3 array piped into iex, R4-4 -EncodedArguments host).

func hasReasonCode(r Result, code ReasonCode) bool {
	for _, u := range r.Unknowns {
		if u.Code == code {
			return true
		}
	}
	for _, e := range r.Effects {
		for _, rr := range e.Reasons {
			if rr.Code == code {
				return true
			}
		}
	}
	return false
}

func hasUnknownTargetKind(r Result, k Kind) bool {
	for _, e := range r.Effects {
		if e.Kind == k && e.TargetState == TargetStateUnknown {
			return true
		}
	}
	return false
}

// R4-2 (a): a comma list / array argument is one operand per element, never one
// fabricated path.
func TestPSReview4CommaListNotOnePath(t *testing.T) {
	t.Run("positional comma list is two deletes", func(t *testing.T) {
		r := Extract(Call{Surface: SurfaceShell, Command: `Remove-Item C:\tmp\a,C:\Windows\System32`}, winPS)
		if !has(r, KindDelete, `c:\tmp\a`, TargetStateKnown) || !has(r, KindDelete, `c:\windows\system32`, TargetStateKnown) {
			t.Fatalf("comma list not split into two deletes: %s", fmtRes(r))
		}
		// the fabricated joined path must not appear.
		if !noPath(r, `c:\tmp\a c:\windows\system32`) {
			t.Fatalf("fabricated joined path present: %s", fmtRes(r))
		}
	})
	t.Run("quoted-element comma list is two deletes", func(t *testing.T) {
		r := Extract(Call{Surface: SurfaceShell, Command: `Remove-Item 'C:\tmp\a','C:\Windows'`}, winPS)
		if !has(r, KindDelete, `c:\tmp\a`, TargetStateKnown) || !has(r, KindDelete, `c:\windows`, TargetStateKnown) {
			t.Fatalf("quoted comma list not split: %s", fmtRes(r))
		}
	})
	t.Run("Copy-Item -Path comma list copies each element", func(t *testing.T) {
		r := Extract(Call{Surface: SurfaceShell, Command: `Copy-Item -Path C:\a,C:\b -Destination C:\dst`}, winPS)
		if !has(r, KindRead, `c:\a`, TargetStateKnown) || !has(r, KindRead, `c:\b`, TargetStateKnown) {
			t.Fatalf("Copy-Item comma sources not both read: %s", fmtRes(r))
		}
		if !has(r, KindWrite, `c:\dst\a`, TargetStateKnown) || !has(r, KindWrite, `c:\dst\b`, TargetStateKnown) {
			t.Fatalf("Copy-Item comma dests not joined per element: %s", fmtRes(r))
		}
	})
	t.Run("a non-literal element stays unknown", func(t *testing.T) {
		r := Extract(Call{Surface: SurfaceShell, Command: `Remove-Item C:\a,$x`}, winPS)
		if !has(r, KindDelete, `c:\a`, TargetStateKnown) {
			t.Fatalf("literal element not a known delete: %s", fmtRes(r))
		}
		if !hasUnknownTargetKind(r, KindDelete) || r.FullyKnown() {
			t.Fatalf("dynamic element should leave an unknown delete: %s", fmtRes(r))
		}
	})
}

// R4-3 (b): a list / array piped into iex / Invoke-Expression is opaque_code,
// never a trusted re-parse; each element is its own script, so its effects are
// present too.
func TestPSReview4ArrayIntoIEXIsOpaque(t *testing.T) {
	for _, c := range []string{
		`'Get-Date','Remove-Item C:\Windows' | iex`,
		`'Get-Date','Remove-Item C:\Windows' | Invoke-Expression`,
	} {
		r := Extract(Call{Surface: SurfaceShell, Command: c}, winPS)
		if !hasReasonCode(r, ReasonOpaqueCode) {
			t.Errorf("%q not opaque_code: %s", c, fmtRes(r))
		}
		if r.FullyKnown() {
			t.Errorf("%q wrongly fully known: %s", c, fmtRes(r))
		}
		// pwsh runs each piped element as its own script, and psparse now gives one
		// script per element, so the delete of the second element is a real effect
		// and must be present. The call stays opaque and not fully known (the
		// assertions above); the delete is not what makes it safe (GAP-0156, R7-M).
		if !has(r, KindDelete, `c:\windows`, TargetStateKnown) {
			t.Errorf("%q lost the delete of c:\\windows that the second element runs: %s", c, fmtRes(r))
		}
	}
}

// R4-4 (c): a powershell/pwsh host carrying -EncodedArguments is opaque; the
// CLIXML args blob is never decoded as the script.
func TestPSReview4EncodedArgsHostIsOpaque(t *testing.T) {
	// base64(utf-16le) of "Remove-Item C:\Windows -Recurse" and a CLIXML args blob.
	ec := `UgBlAG0AbwB2AGUALQBJAHQAZQBtACAAQwA6AFwAVwBpAG4AZABvAHcAcwAgAC0AUgBlAGMAdQByAHMAZQA=`
	ea := `PABPAGIAagBzACAAVgBlAHIAcwBpAG8AbgA9ACIAMQAuADEALgAwAC4AMQAiAD4APABTAD4AeAA8AC8AUwA+ADwALwBPAGIAagBzAD4A`
	for _, c := range []string{
		`powershell -EncodedArguments ` + ea + ` -EncodedCommand ` + ec,
		`pwsh -encodeda ` + ea + ` -ec ` + ec,
		`powershell -ea ` + ea + ` -ec ` + ec,
	} {
		r := Extract(Call{Surface: SurfaceShell, Command: c}, winPS)
		if !hasReasonCode(r, ReasonOpaqueCode) || r.FullyKnown() {
			t.Errorf("encoded-args host not opaque: %s", fmtRes(r))
		}
		if has(r, KindDelete, `c:\windows`, TargetStateKnown) {
			t.Errorf("encoded-args host leaked a known delete: %s", fmtRes(r))
		}
		// the decoded CLIXML must not become a modeled command.
		for _, e := range r.Effects {
			if e.Origin.Program == "objs" {
				t.Errorf("CLIXML args blob was parsed as a command: %s", fmtRes(r))
			}
		}
	}
}
