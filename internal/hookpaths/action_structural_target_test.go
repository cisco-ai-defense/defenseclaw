// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestR104StructuralProtectedNamedPOSIX(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native POSIX fixture")
	}
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	ssh := filepath.Join(home, ".ssh")
	for _, dir := range []string{cwd, ssh, filepath.Join(cwd, "build")} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(ssh, "authorized_keys"), []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{
		`cd ~/.ssh && "$tool" authorized_keys`,
		`pushd ~/.ssh && sh "$script" authorized_keys`,
		`cd ~/.ssh; python3 "$script" authorized_keys`,
		`pushd ~/.ssh; popd; cp payload ~/.ssh/authorized_keys`,
		`cp payload ~/.s*/authorized_keys`,
		`cp payload ~/.ss?/authorized_keys`,
		`for p in ~/.ssh/authorized_k*; do cp payload "$p"; done`,
		`for p in ~/.s*/authorized_keys; do cp payload "$p"; done`,
		`sh -c 'cat "$HOME/.ssh/authorized_keys"'`,
		`cd ~/.ssh && echo authorized_keys`,
		`ls ~/.ssh && echo done`,
	} {
		t.Run(command, func(t *testing.T) {
			if got := ActionCommandDecision(command, cwd, home); got != "protected-target" {
				t.Fatalf("decision = %q, want protected-target", got)
			}
		})
	}
	for _, command := range []string{
		`cd ~/.ssh`, `pushd ~/.ssh`, `ls ~/.ssh`, `ls -o ~/.ssh`, `stat ~/.ssh`,
		`cd ~/.ssh && cat authorized_keys`, `cd ~/.ssh && ls authorized_keys`,
		`cp payload ~/.s*/ordinary.txt`, `cp payload ~/.ssh/*.pub`,
		`pushd build; popd; cp payload authorized_keys`,
	} {
		t.Run("allow/"+command, func(t *testing.T) {
			if got := ActionCommandDecision(command, cwd, home); got != "" {
				t.Fatalf("decision = %q, want allow", got)
			}
		})
	}
}

func TestR104StructuralLessOptions(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	if err := os.Mkdir(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(home, ".ssh", "authorized_keys")
	for _, option := range []string{"--LOG-FILE", "--Log-Fi", "--log-f", "--l", "-o", "-O"} {
		t.Run(option, func(t *testing.T) {
			if got := ActionCommandDecision("less "+option+" "+target, cwd, home); got != "protected-target" {
				t.Fatalf("decision = %q, want protected-target", got)
			}
		})
	}
	if got := ActionCommandDecision("less --LoG-Fi="+target, cwd, home); got != "protected-target" {
		t.Fatalf("attached abbreviated log target decision = %q", got)
	}
	if got := ActionCommandDecision("less "+target, cwd, home); got != "" {
		t.Fatalf("plain read decision = %q", got)
	}
}

func TestR104StructuralProtectedNamedWindows(t *testing.T) {
	const home = `C:\Users\b00`
	const cwd = `C:\work`
	const key = `C:\Users\b00\.ssh\authorized_keys`
	for _, command := range []string{
		`Set-Location ` + home + `\.ssh; & $tool authorized_keys`,
		`Push-Location ` + home + `\.ssh; & $script authorized_keys`,
		`Copy-Item payload C:\Users\b00\.s*\authorized_keys`,
		`Copy-Item payload C:\Users\b00\.ss?\authorized_keys`,
		`Copy-Item payload $root\.ssh\authorized_keys`,
		`Copy-Item payload %ROOT%\.ssh\authorized_keys`,
		`Get-ChildItem ` + home + `\.ssh | Select-Object @{e={Set-Content ` + key + ` marker}}`,
		`Get-Content ` + key + ` | Select-Object {Add-Content ` + key + ` marker}`,
		`Get-ChildItem ` + home + `\.ssh | Select-Object -Property {Set-Content ` + key + ` marker}`,
		`Get-Content (Resolve-Path ` + key + `)`,
		`pwsh -Command 'Get-Content $env:USERPROFILE\.ssh\authorized_keys'`,
		`Push-Location ` + home + `\.ssh; Pop-Location; Add-Content notes.txt ok`,
	} {
		t.Run(command, func(t *testing.T) {
			if got := ActionCommandDecision(command, cwd, home); got != "protected-target" {
				t.Fatalf("decision = %q, want protected-target", got)
			}
		})
	}
	for _, command := range []string{
		`cd ` + home + `\.ssh`, `pushd ` + home + `\.ssh`,
		`ls ` + home + `\.ssh`, `stat ` + home + `\.ssh`,
		`Test-Path ` + home + `\.ssh`, `Resolve-Path ` + home + `\.ssh`,
		`Set-Location ` + home + `\.ssh; Get-Content authorized_keys`,
		`Push-Location C:\work\build; Pop-Location; Add-Content notes.txt ok`,
		`Copy-Item payload C:\Users\b00\.s*\ordinary.txt`,
	} {
		t.Run("allow/"+command, func(t *testing.T) {
			if got := ActionCommandDecision(command, cwd, home); got != "" {
				t.Fatalf("decision = %q, want allow", got)
			}
		})
	}
}
