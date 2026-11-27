// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"slices"
	"testing"
)

// TestPowerShellBareTildeWordIsListedInTheHome (rel-1-0-10:GAP-1191): a bare
// PowerShell word ~\rest or ~/rest names rest in the home (the FileSystem
// provider reads a leading ~ as the home, and pwsh takes \ as a separator on
// Linux and macOS too). The client map lists it as the path in the home, as
// it lists a bare $HOME\rest word, so a managed gateway that cannot place ~
// itself finds the write (Get-Item ~\.defenseclaw\config.yaml).CreateText()
// of a Codex shell call. A quoted ~ is not the home for a .NET argument and
// stays a literal; a ~name or a ~ inside a word is not the home either.
// Red at det111/train-pwsh 98d296ed7e (no bare ~ word listed).
func TestPowerShellBareTildeWordIsListedInTheHome(t *testing.T) {
	home, cwd := "/home/u", "/home/u/proj"
	paths := func(command string) []string {
		operands, over := powerShellQuotedPathOperands(command, cwd, home)
		if over {
			t.Fatalf("%q: over the bound", command)
		}
		var out []string
		for _, o := range operands {
			out = append(out, o.path)
		}
		return out
	}
	for _, c := range []struct {
		command, want string
	}{
		{`$w = (Get-Item ~\.defenseclaw\config.yaml).CreateText(); $w.Close()`, "/home/u/.defenseclaw/config.yaml"},
		{`New-Item -Path ~\.defenseclaw\config.yaml -ItemType File -Value x -Force`, "/home/u/.defenseclaw/config.yaml"},
		{`Set-Content -Path ~/.codex/config.toml -Value x`, "/home/u/.codex/config.toml"},
		{`pwsh -NoProfile -Command "Add-Content -Path ~\.claude\settings.json -Value x"`, "/home/u/.claude/settings.json"},
		{`New-Item -Path ~\proj\notes.txt -Value x -Force`, "/home/u/proj/notes.txt"},
	} {
		if got := paths(c.command); !slices.Contains(got, c.want) {
			t.Errorf("%q: operands %q, want %s listed", c.command, got, c.want)
		}
	}
	for _, command := range []string{
		`Get-Item ~alice\.defenseclaw\config.yaml`,
		`Get-Item x~\.defenseclaw\config.yaml`,
		`Get-Item ~\$env:X\config.yaml`,
	} {
		for _, p := range paths(command) {
			if p == "/home/u/.defenseclaw/config.yaml" || p == "/home/u/$env:X/config.yaml" {
				t.Errorf("%q: listed %s as a path in the home", command, p)
			}
		}
	}
}
