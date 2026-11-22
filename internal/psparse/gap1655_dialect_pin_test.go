// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package psparse

import "testing"

// TestGAP1655Pwsh7NestedCoversLegacyNested pins what the actionfacts launcher
// reading relies on when it reads a payload left unread for legacy quoting
// (actionfacts launcherNestedScripts, rel-1-0-10:GAP-1638): it takes the
// pwsh 7 extraction of the same parse in place of the Windows PowerShell 5.1
// (or unknown) one, which loses nothing only while the legacy-quoting gate is
// the one dialect-dependent branch of ExtractNestedScripts. So for every
// script, both extractions have the same nested scripts in the same order,
// and each one that is not ReasonLegacyQuoting under 5.1 is the same under
// pwsh 7 (kind, text, static, reason).
func TestGAP1655Pwsh7NestedCoversLegacyNested(t *testing.T) {
	corpus := append([]string{}, nestedCorpus()...)
	corpus = append(corpus, fuzzSeeds...)
	corpus = append(corpus, invariantSeeds...)
	corpus = append(corpus,
		`powershell -Command 'Write-Output "x"; Get-Date'`,
		`pwsh -c 'New-Item "HKCU:\x" -Force'`,
		`Write-Output a; powershell -Command 'Remove-Item "C:\x y"'`,
		`cmd /c "echo ""x"""`, `cmd /c 'del "C:\x y"'`,
		`powershell -Command "C:\a b\" x"`, `powershell -Command '' x`,
		`Start-Process powershell -ArgumentList '-c "Get-Date"'`,
		`iex 'Write-Output "x"'`, `[scriptblock]::Create('Write-Output "x"')`,
		`powershell -enc ZQBjAGgAbwAgAGgAaQA=; powershell -c 'Get-Date "x"'`,
	)
	for _, dialect := range []Dialect{DialectWindowsPS51, DialectUnknown} {
		for _, source := range corpus {
			script, _ := Parse(source, Options{Dialect: dialect})
			if script == nil {
				continue
			}
			legacy := ExtractNestedScripts(script)
			asWritten := *script
			asWritten.Dialect = DialectPwsh7
			modern := ExtractNestedScripts(&asWritten)
			if len(modern) != len(legacy) {
				t.Errorf("dialect %d, %q: %d nested under pwsh 7, %d under the legacy dialect", dialect, source, len(modern), len(legacy))
				continue
			}
			for i := range legacy {
				l, m := legacy[i], modern[i]
				if l.Kind != m.Kind {
					t.Errorf("dialect %d, %q #%d: pwsh 7 %s, legacy %s", dialect, source, i, m.Kind, l.Kind)
					continue
				}
				if l.Reason == ReasonLegacyQuoting {
					continue
				}
				if l.Static != m.Static || l.Text != m.Text || l.Reason != m.Reason {
					t.Errorf("dialect %d, %q #%d: pwsh 7 (%v %q %q), legacy (%v %q %q)",
						dialect, source, i, m.Static, m.Text, m.Reason, l.Static, l.Text, l.Reason)
				}
			}
		}
	}
}
