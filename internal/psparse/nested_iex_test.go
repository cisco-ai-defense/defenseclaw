// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package psparse

import "testing"

// TestNestedIEXList is the review-4 R4-3 regression: an array piped into
// Invoke-Expression runs each element as its own script, so psparse must emit
// one nested script per element and never join them. (The nested golden oracle
// does not model iex, so this is a direct test.)
func TestNestedIEXList(t *testing.T) {
	cases := []struct {
		src   string
		texts []string // expected static nested Text values, in order
	}{
		{`'Get-Date','Remove-Item C:\Windows' | iex`, []string{"Get-Date", `Remove-Item C:\Windows`}},
		{`'Write-Output A1','Write-Output B1' | Invoke-Expression`, []string{"Write-Output A1", "Write-Output B1"}},
		{`'a',$x | iex`, []string{"a"}}, // $x element is non-static, not joined
	}
	for _, tc := range cases {
		sc, _ := Parse(tc.src, Options{})
		ns := ExtractNestedScripts(sc)
		var got []string
		for _, n := range ns {
			if n.Kind != KindIEXLiteral {
				continue
			}
			if n.Static {
				got = append(got, n.Text)
			}
		}
		if len(got) != len(tc.texts) {
			t.Errorf("%q: static nested texts = %q, want %q", tc.src, got, tc.texts)
			continue
		}
		for i := range got {
			if got[i] != tc.texts[i] {
				t.Errorf("%q: element %d = %q, want %q", tc.src, i, got[i], tc.texts[i])
			}
		}
	}
}
