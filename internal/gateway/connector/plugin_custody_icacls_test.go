// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"strings"
	"testing"
)

// GAP-0731 review 3: the printed Windows repair clears every refused account
// and passes every path and account to icacls as an inert literal. The rows run
// on every platform; the DACL lookup that feeds them is covered by the safefile
// Windows tests.
func TestGAP0731IcaclsRemovalFix(t *testing.T) {
	const opencode = `C:\Users\lane\.config\opencode`
	const config = `C:\Users\lane\.config`

	t.Run("one account", func(t *testing.T) {
		fix, failing := icaclsRemovalFix([]icaclsRefusedEntry{{trustee: `HOST\other`, carriers: []string{opencode}}})
		if want := `icacls 'C:\Users\lane\.config\opencode' /remove:g 'HOST\other'`; fix != want {
			t.Fatalf("fix=%q, want %q", fix, want)
		}
		if len(failing) != 1 || failing[0] != opencode {
			t.Fatalf("failing=%q", failing)
		}
	})

	t.Run("two accounts are both removed", func(t *testing.T) {
		fix, failing := icaclsRemovalFix([]icaclsRefusedEntry{
			{trustee: `HOST\other`, carriers: []string{opencode}},
			{trustee: `HOST\third`, carriers: []string{config, opencode}},
		})
		for _, want := range []string{
			`icacls 'C:\Users\lane\.config\opencode' /remove:g 'HOST\other'`,
			`icacls 'C:\Users\lane\.config' /remove:g 'HOST\third'`,
			`icacls 'C:\Users\lane\.config\opencode' /remove:g 'HOST\third'`,
		} {
			if !strings.Contains(fix, want) {
				t.Fatalf("fix lacks %q:\n%s", want, fix)
			}
		}
		if strings.Count(fix, "icacls ") != 3 || strings.Contains(fix, "&&") {
			t.Fatalf("want three semicolon-separated commands:\n%s", fix)
		}
		if len(failing) != 2 || failing[0] != config || failing[1] != opencode {
			t.Fatalf("failing=%q, want each folder once, outermost first", failing)
		}
	})

	t.Run("a deny entry is removed with the deny scope", func(t *testing.T) {
		fix, _ := icaclsRemovalFix([]icaclsRefusedEntry{{trustee: `HOST\other`, deny: true, carriers: []string{opencode}}})
		if !strings.Contains(fix, `/remove:d 'HOST\other'`) {
			t.Fatalf("fix=%q", fix)
		}
	})

	// A folder or account name is data: PowerShell must not expand a variable,
	// a subexpression or an escape in it, and a quote in it cannot end the
	// literal.
	t.Run("names are inert literals", func(t *testing.T) {
		for _, name := range []string{`C:\Users\lane\$env`, `C:\Users\lane\$(calc)`, "C:\\Users\\lane\\a`b", `C:\Users\o'brien\x`} {
			fix, _ := icaclsRemovalFix([]icaclsRefusedEntry{{trustee: `HOST\$user`, carriers: []string{name}}})
			if strings.Contains(fix, `"`) {
				t.Fatalf("%q: a double-quoted argument expands in PowerShell:\n%s", name, fix)
			}
			quoted := "'" + strings.ReplaceAll(name, "'", "''") + "'"
			if !strings.Contains(fix, "icacls "+quoted+" /remove:g '") || !strings.Contains(fix, `'HOST\$user'`) {
				t.Fatalf("%q: arguments are not single-quoted literals:\n%s", name, fix)
			}
		}
	})

	t.Run("nothing to remove", func(t *testing.T) {
		if fix, failing := icaclsRemovalFix(nil); fix != "" || len(failing) != 0 {
			t.Fatalf("fix=%q failing=%q", fix, failing)
		}
	})
}
