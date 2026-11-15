// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

// rel-1-0-10:GAP-0801: New-Item makes a link only for a link item type; a
// file or a folder makes none, so it no longer counts as link-making code.
func TestNewItemMayMakeLinkOnlyForALinkItemType(t *testing.T) {
	for _, tc := range []struct {
		command string
		want    bool
	}{
		{`New-Item -Path .\e.txt -ItemType File -Force`, false},
		{`New-Item -Path .\e.txt -Force`, false},
		{`New-Item .\logs -ItemType Directory`, false},
		{`New-Item -Path .\e.txt -ItemType 'file' -Value 'hello world'`, false},
		{`New-Item -Path .\e.txt -ItemType:File`, false},
		{`New-Item -Path .\e.txt -it File`, false},
		{"Set-Content -Path .\\a.txt -Value 'one'\nNew-Item -Path .\\e.txt -ItemType File -Force", false},
		// A link item type, or one the reading cannot fix, still may.
		{`New-Item -Path .\l -ItemType SymbolicLink -Target .\a`, true},
		{`New-Item -Path .\l -ItemType Junction -Target .\a`, true},
		{`New-Item -Path .\l -ItemType HardLink -Value .\a`, true},
		{`New-Item -Path .\l -ItemType:SymbolicLink -Target .\a`, true},
		{`New-Item -Path .\l -ItemType $kind -Target .\a`, true},
		{`New-Item @params`, true},
		{`New-Item -Path .\l -ItemType File -ItemType SymbolicLink -Target .\a`, true},
		{`New-Item -Path .\l -ItemType Thing`, true},
		{`Write-Output "New-Item" ; New-Item -Path .\e.txt`, true},
		{`Invoke-Expression 'New-Item -Path .\e.txt'`, true},
		// A call the parse cannot spell (a dynamic value leaves no argv)
		// keeps the conservative answer.
		{`New-Item -Path .\e.txt -Type File -Value $content`, true},
	} {
		if got := CommandMayMakeLink(tc.command); got != tc.want {
			t.Errorf("CommandMayMakeLink(%q) = %v, want %v", tc.command, got, tc.want)
		}
	}
}
