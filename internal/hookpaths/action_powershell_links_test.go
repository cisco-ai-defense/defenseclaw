// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"runtime"
	"testing"
)

// TestPowerShellLinkTwin: the PowerShell link and move spellings that the
// shell link reader can follow become the ln and mv they are; anything else
// that makes a link, or that the twin cannot place, keeps the opaque reading
// (rel-1-0-10:GAP-0749).
func TestPowerShellLinkTwin(t *testing.T) {
	const link = "New-Item -ItemType SymbolicLink -Path /p/link -Target /p/uuid"
	rows := []struct {
		name, command, want string
	}{
		{"symbolic link", link, "ln -s -- '/p/uuid' '/p/link'"},
		{"link then move", link + "; Move-Item /p/link /p/link2", "ln -s -- '/p/uuid' '/p/link'\nmv -- '/p/link' '/p/link2'"},
		{"link, move and remove", link + "\nMove-Item -Path /p/link -Destination /p/link2 -Force\nRemove-Item /p/link2", "ln -s -- '/p/uuid' '/p/link'\nmv -- '/p/link' '/p/link2'"},
		{"hard link", "New-Item -ItemType HardLink -Path /p/h -Target /p/uuid", "ln -- '/p/uuid' '/p/h'"},
		{"junction with -Value", "New-Item -ItemType Junction -Path /p/j -Value /p/uuid", "ln -s -- '/p/uuid' '/p/j'"},
		{"alias and positional path", "ni -ItemType SymbolicLink /p/link -Target /p/uuid", "ln -s -- '/p/uuid' '/p/link'"},
		{"a file beside the link", "New-Item -ItemType File -Path /p/f; " + link, "ln -s -- '/p/uuid' '/p/link'"},
		// Kept opaque.
		{"dynamic target", "New-Item -ItemType SymbolicLink -Path /p/link -Target $env:X", ""},
		{"dynamic name", "New-Item -ItemType SymbolicLink -Path $x -Target /p/uuid", ""},
		{"directory change first", "Set-Location /p; " + link, ""},
		{"copy beside the link", "Copy-Item /p/a /p/b; " + link, ""},
		{"rename beside the link", link + "; Rename-Item /p/link link2", ""},
		{"a name from -Name", "New-Item -ItemType SymbolicLink -Path /p -Name link -Target /p/uuid", ""},
		{"one link read, one other link API", link + "; cmd /c mklink /p/l2 /p/uuid", ""},
		{"link API in code", "[System.IO.File]::CreateSymbolicLink('/p/l','/p/t')", ""},
		{"no link at all", "Move-Item /p/a /p/b", ""},
		{"move with an unknown switch", link + "; Move-Item /p/link /p/link2 -Recurse", ""},
	}
	for _, row := range rows {
		got, ok := powerShellLinkTwin(row.command, "/p", "/home/u")
		if row.want == "" {
			if ok {
				t.Errorf("%s: read as %q, want the opaque reading", row.name, got)
			}
			continue
		}
		if !ok || got != row.want {
			t.Errorf("%s: twin %q (ok %v), want %q", row.name, got, ok, row.want)
		}
	}
	if runtime.GOOS != "windows" {
		// A drive path is not a path on this host: the opaque reading stays.
		if got, ok := powerShellLinkTwin(`New-Item -ItemType SymbolicLink -Path C:\p\link -Target C:\p\uuid`, "/p", "/home/u"); ok {
			t.Errorf("a drive path is read as %q on %s", got, runtime.GOOS)
		}
	}
}
