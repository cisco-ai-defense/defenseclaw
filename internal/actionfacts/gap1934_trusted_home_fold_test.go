// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"testing"
)

// GAP-1934: rewriteTrustedShellHome tested lower[index:] (strings.ToLower of
// the source) at source offsets. Kelvin signs (3 bytes, lowered to 1) before
// the home anchor made it slice past the end of lower and panic; a growing
// letter (U+023A) moved the anchor and the home rewrite was lost. Each source
// is now rewritten as its ASCII twin is.
func TestGAP1934TrustedShellHomeCaseChangingLetters(t *testing.T) {
	home, ok := normalizeActiveHome(`C:\Users\alice`)
	if !ok {
		t.Fatal("normalizeActiveHome refused the test home")
	}
	const twinLetters = "xxxxxxxxxxxxxxxxxxxx"
	for _, letters := range []string{strings.Repeat(gap1914Kelvin, 20), strings.Repeat(gap1914Grow, 20), strings.Repeat(gap1914DotI, 20)} {
		for _, dialect := range []Dialect{DialectPowerShell, DialectCMD} {
			anchor := "$HOME"
			if dialect == DialectCMD {
				anchor = "%USERPROFILE%"
			}
			source := "Write-Output '" + letters + "' ; type " + anchor + `\docs\a.txt`
			twin := strings.Replace(source, letters, twinLetters, 1)
			wantOut, wantOK := rewriteTrustedShellHome(twin, home, dialect, false)
			if !wantOK {
				t.Fatalf("%v: the ASCII twin %q was not rewritten; the test lost its subject", dialect, twin)
			}
			var got string
			var gotOK bool
			gap1914NoPanic(t, "rewriteTrustedShellHome", func() { got, gotOK = rewriteTrustedShellHome(source, home, dialect, false) })
			if want := strings.Replace(wantOut, twinLetters, letters, 1); !gotOK || got != want {
				t.Errorf("%v: rewriteTrustedShellHome(%q) = %q, %v; want %q, true as for the ASCII twin", dialect, source, got, gotOK, want)
			}
		}
	}
}
