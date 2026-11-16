// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// TestR105WindowsKeyReadInsideAnExpression (GAP-2397, GAP-1779 review row
// RV1-1): on a Windows home a private-key read is a key read wherever the
// shell evaluates it: a grouping, subexpression or array expression, a
// $(...) inside a double-quoted string or an expandable here-string, the
// right side of an assignment, the path of a .NET file read, and a Git Bash
// for loop over the key glob (GAP-1780). Text the shell does not evaluate
// (single quotes, a bare ( inside double quotes, comments, literal
// here-strings) and reads of ordinary files stay allowed.
func TestR105WindowsKeyReadInsideAnExpression(t *testing.T) {
	const home, cwd = `C:\Users\u`, `C:\Users\u\proj`
	for _, tc := range []struct {
		command string
		want    bool
	}{
		{`(Get-Content ~\.ssh\id_ed25519)`, true},
		{`Write-Output (Get-Content ~\.ssh\id_ed25519)`, true},
		{`Write-Output (Get-Content '~/.ssh/id_ed25519')`, true},
		{`Write-Output (Get-Content $HOME\.ssh\id_ed25519 -Raw)`, true},
		{`Write-Host (gc ~/.ssh/id_ed25519)`, true},
		{`"$(Get-Content $HOME\.ssh\id_ed25519)"`, true},
		{`Write-Output "$(Get-Content '~/.ssh/id_ed25519')"`, true},
		{`Write-Output @(Get-Content ~\.ssh\id_rsa)`, true},
		{`$k = Get-Content ~/.ssh/id_ed25519; $k`, true},
		{`[string]$k = gc ~\.ssh\id_ed25519; $k`, true},
		{`$k=Get-Content ~\.ssh\id_ed25519`, true},
		{`[IO.File]::ReadAllText("$HOME\.ssh\id_ed25519")`, true},
		{`[System.IO.File]::ReadAllBytes('C:\Users\u\.ssh\id_ed25519')`, true},
		{`Write-Output (cat ~/.ssh/id_ed25519)`, true},
		{`k=$(cat ~/.ssh/id_ed25519); echo "$k"`, true},
		{`echo "$(head -c 4096 ~/.ssh/id_ed25519)"`, true},
		{"$t = @\"\n$(Get-Content ~\\.ssh\\id_ed25519)\n\"@\n$t", true},
		{`for f in ~/.ssh/id_*; do cat "$f"; done`, true},
		{`for f in ~/.ssh/id_*; do head -c 4096 ${f}; done`, true},
		// Controls.
		{`Write-Output (Get-Content .\notes.txt)`, false},
		{`Write-Output (Get-Content ~\.ssh\id_ed25519.pub)`, false},
		{`Write-Output '(Get-Content ~\.ssh\id_ed25519)'`, false},
		{`Write-Output '$(Get-Content ~\.ssh\id_ed25519)'`, false},
		{`Write-Output "(Get-Content ~\.ssh\id_ed25519) prints the key"`, false},
		{"# Write-Output (Get-Content ~\\.ssh\\id_ed25519)\nGet-Date", false},
		{"$t = @'\n$(Get-Content ~\\.ssh\\id_ed25519)\n'@\nSet-Content notes.md $t", false},
		{`$k = Get-Content README.md; $k`, false},
		{`[IO.File]::ReadAllText("$HOME\proj\notes.txt")`, false},
		{`[IO.File]::WriteAllText("notes.txt", "x")`, false},
		{`for f in *.txt; do cat "$f"; done`, false},
		{`Write-Output (Get-ChildItem ~\.ssh).Count`, false},
		{`git log --oneline -5`, false},
	} {
		if got := ActionPrivateKeyRead(tc.command, cwd, home); got != tc.want {
			t.Errorf("ActionPrivateKeyRead(%q) = %t, want %t", tc.command, got, tc.want)
		}
	}
}

// TestR105WindowsKeyGlobThroughALink (GAP-1780 Windows leg): on a Windows host
// a key glob through a directory junction (dirlink -> ~\.ssh) or a file
// symlink is expanded on the host and each match resolved, as on POSIX.
func TestR105WindowsKeyGlobThroughALink(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("needs a Windows file system")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "h")
	project := filepath.Join(home, "proj")
	for _, dir := range []string{filepath.Join(home, ".ssh"), project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{`.ssh\id_ed25519`, `.ssh\id_ed25519.pub`, `proj\notes.txt`} {
		if err := os.WriteFile(filepath.Join(home, file), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", filepath.Join(project, "dirlink"), filepath.Join(home, ".ssh")).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v %s", err, out)
	}
	for _, command := range []string{
		"head -c 4096 dirlink/id_*",
		`Get-Content dirlink\id_*`,
		"for f in dirlink/id_*; do cat \"$f\"; done",
	} {
		if !ActionPrivateKeyRead(command, project, home) {
			t.Errorf("ActionPrivateKeyRead(%q) = false, want a key read through the junction", command)
		}
	}
	if err := os.Symlink(filepath.Join(home, ".ssh", "id_ed25519"), filepath.Join(project, "keyl")); err == nil {
		if !ActionPrivateKeyRead("cat keyl*", project, home) {
			t.Error("cat keyl* through a file symlink is a key read")
		}
	} else {
		t.Logf("file symlink not available here: %v", err)
	}
	for _, command := range []string{"head -n 5 note*", "cat dirlink/id_*.pub", "Get-ChildItem dirlink"} {
		if ActionPrivateKeyRead(command, project, home) {
			t.Errorf("ActionPrivateKeyRead(%q) = true, want no key read", command)
		}
	}
}
