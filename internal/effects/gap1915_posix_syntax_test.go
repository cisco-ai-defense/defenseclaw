// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import "testing"

func TestGAP1915POSIXOnlySyntax(t *testing.T) {
	for _, cmd := range []string{`find . -name x \;`, "cat <<EOF\nx\nEOF", "echo 'a'\\''b'"} {
		if !posixOnlySyntax(cmd) {
			t.Errorf("%q: not POSIX-only syntax", cmd)
		}
	}
	for _, cmd := range []string{`Write-Output 'it''s'`, `Get-Content C:\t\a.txt | Out-File C:\t\b.txt`, "cmd /c dir > C:\\t\\x"} {
		if posixOnlySyntax(cmd) {
			t.Errorf("%q: read as POSIX-only syntax", cmd)
		}
	}
}
