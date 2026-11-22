// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package psparse

import "testing"

// TestGAP0198WorkingDirectoryValueIsNotTheScript pins the -WorkingDirectory
// host switch: its value is one word that is not part of the script, so the
// launcher's script stays static text, also when the value names a folder
// from the caller's home or environment ($HOME\.defenseclaw, the spelling of
// the live repro). A value that may become several words (a bare variable, a
// splat, a sub-expression) or a folder word after any other switch keeps the
// launcher opaque (rel-1-0-10:GAP-0198).
func TestGAP0198WorkingDirectoryValueIsNotTheScript(t *testing.T) {
	const script = `Set-Content -Path config.yaml -Value m`
	static := []string{
		`pwsh -NoProfile -wd C:\Users\alice\.defenseclaw -Command "` + script + `"`,
		`pwsh -WorkingDirectory 'C:\Users\alice\.defenseclaw' -c '` + script + `'`,
		`pwsh -NoProfile -wd $HOME\.defenseclaw -Command "` + script + `"`,
		`powershell -wd "$HOME\.defenseclaw" -Command "` + script + `"`,
		`pwsh -wd "${env:USERPROFILE}\.defenseclaw" -c '` + script + `'`,
		`pwsh -wd $env:USERPROFILE\.defenseclaw -nop -c '` + script + `'`,
	}
	for _, src := range static {
		nested := hostNested(t, src)
		if !nested.Static || nested.Text != script {
			t.Errorf("%s: static=%v text=%q reason=%q, want the static script", src, nested.Static, nested.Text, nested.Reason)
		}
	}
	opaque := []string{
		`pwsh -wd $dir -c '` + script + `'`,
		`pwsh -wd @dirs -c '` + script + `'`,
		`pwsh -wd "$(Get-Location)\x" -c '` + script + `'`,
		`pwsh -wd "$dir\x" -c '` + script + `'`,
		`pwsh -wd:$HOME -c '` + script + `'`,
		`pwsh -ep $HOME\x -c '` + script + `'`,
		`pwsh -wd -c '` + script + `'`,
		`pwsh -wd $HOME,$PWD -c '` + script + `'`,
	}
	for _, src := range opaque {
		if nested := hostNested(t, src); nested.Static {
			t.Errorf("%s: static %q, want an opaque launcher", src, nested.Text)
		}
	}
}

func hostNested(t *testing.T, src string) NestedScript {
	t.Helper()
	sc, _ := Parse(src, Options{})
	all := ExtractNestedScripts(sc)
	if len(all) != 1 {
		t.Fatalf("%s: %d nested scripts, want 1", src, len(all))
	}
	return all[0]
}
