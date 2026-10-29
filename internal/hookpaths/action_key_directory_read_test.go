// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// RV22-1 (GAP-2168, GAP-0281): grep and Select-String count as plain readers
// under the GAP-2168 ruling, so a recursive read of the whole .ssh directory
// lost its block, and it prints every private key. A content reader whose
// operand is the key directory is a key read; a named file stays a plain
// read.
func TestActionRecursiveReadOfTheKeyDirectoryIsAKeyRead(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home")
	}
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	for _, dir := range []string{filepath.Join(home, ".ssh", "old"), cwd} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"id_ed25519", "id_ed25519.pub", "config", "authorized_keys"} {
		if err := os.WriteFile(filepath.Join(home, ".ssh", name), []byte("decoy\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(home, ".ssh"), filepath.Join(cwd, "sshlink")); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{
		"grep -r . ~/.ssh", "grep -r . ~/.ssh/", "grep -R . ~/.ssh", "grep --recursive . ~/.ssh",
		"grep -d recurse . ~/.ssh", "grep --directories=recurse . ~/.ssh", "grep -rI BEGIN ~/.ssh",
		"egrep -r . ~/.ssh", "fgrep -r a ~/.ssh", `grep -rh . "$HOME/.ssh"`, `grep -r . "$HOME"/.ssh`,
		"cd ~/.ssh && grep -r . .", "cd ~/.ssh; grep -r BEGIN", "grep -r --include='id_*' . ~/.ssh",
		"grep -re . ~/.ssh", "grep -r -e BEGIN -e END ~/.ssh", "grep -rl . sshlink", "grep -r . ~/.ssh/old",
		"rg . ~/.ssh", "rg -uu BEGIN ~/.ssh", "cd ~/.ssh && rg BEGIN", "sudo grep -r . ~/.ssh",
		`grep -r . ~/.ssh; status=$?; printf '\n[exit status] %s\n' "$status"; exit "$status"`,
	} {
		if !ActionPrivateKeyRead(command, cwd, home) {
			t.Errorf("ActionPrivateKeyRead(%q) = false, want a key read", command)
		}
	}
	for _, command := range []string{
		"grep -r Host ~/.ssh/config", "grep -r marker ~/.ssh/authorized_keys", "grep -rn TODO .",
		"grep . ~/.ssh", "rg TODO", "rg TODO src", "grep -r ssh ~/.ssh/id_ed25519.pub",
		"grep -r --include='*.go' x .", "cd ~/.ssh && ls", "cd ~/.ssh && grep Host config",
		"cd ~/.ssh && grep -r Host config", "cd /tmp && grep -r . .", "grep -r ssh ~/.sshrc",
		"ls -la ~/.ssh", "grep -c marker ~/.ssh/authorized_keys", "wc -l ~/.ssh/authorized_keys",
	} {
		if ActionPrivateKeyRead(command, cwd, home) {
			t.Errorf("ActionPrivateKeyRead(%q) = true, want no key read", command)
		}
	}
}

func TestActionWindowsListedKeyDirectoryPipedToAReaderIsAKeyRead(t *testing.T) {
	const home, cwd = `C:\Users\u`, `C:\Users\u\proj`
	for _, command := range []string{
		`Get-ChildItem $HOME\.ssh | Select-String -Pattern .`,
		`Get-ChildItem $HOME\.ssh -Recurse | Select-String .`,
		`Get-ChildItem $HOME\.ssh | Get-Content`,
		`gci ~\.ssh -Force | sls BEGIN`,
		`dir -Path $env:USERPROFILE\.ssh | Where-Object Length -gt 0 | Get-Content`,
		`Get-ChildItem $HOME\.ssh\id_* | Get-Content`,
		`Set-Location ~; Get-ChildItem .ssh | Select-String .`,
		"grep -r . ~/.ssh", "grep -r . /c/Users/u/.ssh", "cd /c/Users/u/.ssh && grep -r . .",
	} {
		if !ActionPrivateKeyRead(command, cwd, home) {
			t.Errorf("ActionPrivateKeyRead(%q) = false, want a key read", command)
		}
	}
	for _, command := range []string{
		`Get-ChildItem $HOME\.ssh`, `Get-ChildItem $HOME\.ssh | Select-Object Name`,
		`Get-ChildItem $HOME\.ssh -Filter *.pub | Get-Content`, `Get-ChildItem $HOME\.ssh\*.pub | Get-Content`,
		`Get-ChildItem . -Recurse | Select-String TODO`, `Get-ChildItem $HOME\.ssh\config | Get-Content`,
		`Get-Content $HOME\.ssh\config | Select-String Host`, "grep -r Host ~/.ssh/config",
		`Get-ChildItem $HOME\.ssh; Get-Content notes.txt | Select-String x`,
	} {
		if ActionPrivateKeyRead(command, cwd, home) {
			t.Errorf("ActionPrivateKeyRead(%q) = true, want no key read", command)
		}
	}
}
