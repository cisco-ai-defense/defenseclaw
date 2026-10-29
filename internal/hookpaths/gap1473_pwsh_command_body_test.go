// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// GAP-1473 (POSIX leg): pwsh -Command with a body that only prints or runs
// a read-only git command passes a quoted ~ path as text, as the body does
// on its own, so it is not a protected-named write. Every writer body
// (Copy-Item, Out-File, Add-Content, a redirect, a substitution that runs a
// writer, a later cp) keeps the protected-target decision (GAP-2417 rows).
func TestActionPwshCommandPrintBodyQuotedTildeIsText(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home")
	}
	home := t.TempDir()
	cwd := home + "/proj"
	q := func(s string) string { return strings.ReplaceAll(s, "@", string(rune(39))) }
	for _, tc := range []struct{ command, want string }{
		{q(`pwsh -Command "git commit --allow-empty -m @Document ~/.ssh/authorized_keys@"`), ""},
		{q(`pwsh -NoProfile -c "Write-Output @~/.ssh/authorized_keys@"`), ""},
		{q(`powershell -NoLogo -NonInteractive -Command "echo @~/.ssh/authorized_keys@"`), ""},
		{q(`pwsh -ExecutionPolicy Bypass -Command "Write-Host @see ~/.ssh/authorized_keys@; git status"`), ""},
		{q(`pwsh -Command "Copy-Item k.pub @~/.ssh/authorized_keys@"`), "protected-target"},
		{q(`pwsh -Command "Write-Output k >> @~/.ssh/authorized_keys@"`), "protected-target"},
		{q(`pwsh -Command "Write-Output k | Out-File -Append @~/.ssh/authorized_keys@"`), "protected-target"},
		{q(`pwsh -Command "Write-Output @~/.ssh/authorized_keys@; Add-Content @~/.ssh/authorized_keys@ k"`), "protected-target"},
		{q(`pwsh -Command "Write-Output $(Copy-Item k.pub @~/.ssh/authorized_keys@)"`), "protected-target"},
		{q(`pwsh -Command "git commit -m x; cp k.pub ~/.ssh/authorized_keys"`), "protected-target"},
		{q(`pwsh -Command "echo k >> ~/.ssh/authorized_keys"`), "protected-target"},
		{q(`pwsh -File x.ps1 @~/.ssh/authorized_keys@`), "protected-target"},
	} {
		if got := ActionCommandDecisionWithDialectAndGlobFacts(tc.command, cwd, home, "", nil); got != tc.want {
			t.Errorf("%q = %q, want %q", tc.command, got, tc.want)
		}
	}
}

// GAP-1473 RV18-1 (Windows home): the same print-only or read-only git
// pwsh -Command bodies pass a quoted ~ as text when the home is a Windows
// home, under every dialect hint; every writer body still blocks.
func TestActionPwshCommandPrintBodyQuotedTildeIsTextOnWindowsHome(t *testing.T) {
	home := `C:\Users\b00`
	cwd := home + `\proj`
	q := func(s string) string { return strings.ReplaceAll(s, "@", string(rune(39))) }
	for _, tc := range []struct{ command, want string }{
		{q(`pwsh -Command "git commit --allow-empty -m @Document ~/.ssh/authorized_keys@"`), ""},
		{q(`pwsh -Command "Write-Output @~/.ssh/authorized_keys@"`), ""},
		{q(`pwsh -NoProfile -c "echo @~/.ssh/authorized_keys@"`), ""},
		{q(`powershell.exe -NoLogo -Command "Write-Host @see ~/.ssh/authorized_keys@; git status"`), ""},
		{q(`pwsh -Command "Copy-Item k.pub @~/.ssh/authorized_keys@"`), "protected-target"},
		{q(`pwsh -Command "Write-Output k >> @~/.ssh/authorized_keys@"`), "protected-target"},
		{q(`pwsh -Command "Write-Output k | Out-File -Append @~/.ssh/authorized_keys@"`), "protected-target"},
		{q(`pwsh -Command "Write-Output @~/.ssh/authorized_keys@; Add-Content @~/.ssh/authorized_keys@ k"`), "protected-target"},
		{q(`pwsh -Command "Write-Output $(Copy-Item k.pub @~/.ssh/authorized_keys@)"`), "protected-target"},
		{q(`pwsh -Command "Write-Output @(Copy-Item k.pub @~/.ssh/authorized_keys@)"`), "protected-target"},
		{q(`pwsh -Command "Write-Output (Set-Content @~/.ssh/authorized_keys@ k)"`), "protected-target"},
		{q(`pwsh -Command "git commit -m x; cp k.pub ~/.ssh/authorized_keys"`), "protected-target"},
		{q(`pwsh -Command "Write-Output @~/.ssh/authorized_keys@" > ~/.ssh/authorized_keys`), "protected-target"},
		{q(`pwsh -Command "Write-Output @~/.ssh/authorized_keys@"; Copy-Item k.pub ~/.ssh/authorized_keys`), "protected-target"},
		{q(`pwsh -Command "echo k >> ~/.ssh/authorized_keys"`), "protected-target"},
	} {
		for _, dialect := range []actionfacts.Dialect{"", actionfacts.DialectPowerShell, actionfacts.DialectPOSIX} {
			got := ActionCommandDecisionWithDialectAndGlobFacts(tc.command, cwd, home, dialect, nil)
			if (got == "") != (tc.want == "") {
				t.Errorf("%q dialect %q = %q, want %q", tc.command, dialect, got, tc.want)
			}
		}
	}
}
