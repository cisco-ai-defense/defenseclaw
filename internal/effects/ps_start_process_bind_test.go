// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/psparse"
)

// TestPSStartProcessChildBinding: the Start-Process child is bound as
// PowerShell binds it -- a valued parameter (-WindowStyle, -Verb, -WorkingDirectory)
// takes its value before the first positional is read as the FilePath, a switch
// takes none, and an unknown or ambiguous parameter leaves the call a shell
// target when any argument names a shell (DET111 R1, GAP-1655 parser
// differential found by the S3-PRE security review).
func TestPSStartProcessChildBinding(t *testing.T) {
	for _, tc := range []struct {
		src  string
		want bool
	}{
		{`Start-Process -WindowStyle Hidden powershell -ArgumentList 'x'`, true},
		{`Start-Process -Verb RunAs cmd`, true},
		{`Start-Process -WorkingDirectory C:\w pwsh`, true},
		{`Start-Process -Wait powershell`, true},
		{`Start-Process -W Hidden powershell`, true}, // ambiguous prefix
		{`Start-Process -Bogus x powershell`, true},  // unknown parameter
		{`Start-Process powershell`, true},
		{`Start-Process -FilePath cmd`, true},
		{`Start-Process notepad -ArgumentList powershell`, false},
		{`Start-Process -WindowStyle Hidden notepad`, false},
		{`Start-Process -Wait notepad`, false},
	} {
		sc, err := psparse.Parse(tc.src, psparse.Options{})
		if err != nil || len(sc.Statements) != 1 {
			t.Fatalf("%q: parse %v", tc.src, err)
		}
		var got bool
		collectPSCommands(sc.Statements, 0, func(c *psparse.Command) { got = got || psStartProcessShellTarget(c) })
		if got != tc.want {
			t.Errorf("%q: shell target %v, want %v", tc.src, got, tc.want)
		}
	}
}
