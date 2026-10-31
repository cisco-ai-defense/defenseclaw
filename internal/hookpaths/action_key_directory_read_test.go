// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

// RV22-1 (GAP-2168, GAP-0281): grep and Select-String count as plain readers
// under the GAP-2168 ruling, so a recursive read of the whole .ssh directory
// lost its block, and it prints every private key. A content reader whose
// operand is the key directory is a key read; a named file stays a plain
// read.
func TestActionRecursiveReadOfTheKeyDirectoryIsAKeyRead(t *testing.T) {
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
		if !posixShellPrivateKeyRead(command, cwd, home) {
			t.Errorf("posixShellPrivateKeyRead(%q) = false, want a key read", command)
		}
	}
	for _, command := range []string{
		"grep -r Host ~/.ssh/config", "grep -r marker ~/.ssh/authorized_keys", "grep -rn TODO .",
		"grep . ~/.ssh", "rg TODO", "rg TODO src", "grep -r ssh ~/.ssh/id_ed25519.pub",
		"grep -r --include='*.go' x .", "cd ~/.ssh && ls", "cd ~/.ssh && grep Host config",
		"cd ~/.ssh && grep -r Host config", "cd /tmp && grep -r . .", "grep -r ssh ~/.sshrc",
		"ls -la ~/.ssh", "grep -c marker ~/.ssh/authorized_keys", "wc -l ~/.ssh/authorized_keys",
	} {
		if posixShellPrivateKeyRead(command, cwd, home) {
			t.Errorf("posixShellPrivateKeyRead(%q) = true, want no key read", command)
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

// GAP-2421 (checker pod23, regression of adf114dba5): the cd tracking kept
// every earlier directory as a candidate, so cd ~/.ssh && cd /proj && grep
// -rn TODO . was a key read although grep runs only in /proj. A call that
// needs cd <absolute dir> to succeed reads there; a failed, relative,
// subshell or undone directory change keeps the earlier candidates.
func TestActionKeyReadAfterACertainDirectoryChange(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	// The shell spells the directory with slashes (C:/... on Git Bash).
	dir := filepath.ToSlash(cwd)
	for _, dir := range []string{filepath.Join(home, ".ssh"), cwd} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "id_ed25519"), []byte("decoy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{
		"cd ~/.ssh && cd " + dir + " && grep -rn TODO .",
		"cd ~/.ssh && cd ~/proj && grep -rn TODO .",
		"cd ~/.ssh; cd " + dir + " && grep -rn TODO .",
		"cd ~/.ssh && cd " + dir + " && grep -rn TODO . | head",
		"pushd ~/.ssh && pushd " + dir + " && rg TODO",
		"cd ~/.ssh && ls && cd " + dir + " && grep -rn TODO .",
		"cd ~/.ssh && cd " + dir + " && { ls; grep -rn TODO .; }",
		"cd ~/.ssh && cd " + dir + " && (make test; grep -rn TODO .)",
	} {
		if posixShellPrivateKeyRead(command, cwd, home) {
			t.Errorf("posixShellPrivateKeyRead(%q) = true, want no key read", command)
		}
	}
	for _, command := range []string{
		"cd ~/.ssh; cd /nonexistent; grep -r . .",
		"cd ~/.ssh && (cd " + dir + ") && grep -r . .",
		"cd " + dir + " && cd ~/.ssh && grep -r . .",
		"cd ~/.ssh; (cd " + dir + " && true); grep -r . .",
		"cd ~/.ssh; cd " + dir + " && true; grep -r . .",
		"cd ~/.ssh && cd " + dir + " || grep -r . .",
		"cd ~/.ssh && { cd " + dir + " && true; }; grep -r . .",
		"cd ~/.ssh && cd " + dir + " && cd - && grep -r . .",
		"pushd ~/.ssh && pushd " + dir + " && popd && grep -r . .",
		"cd ~/.ssh && cd " + dir + " && cd .. && grep -r . .ssh",
		"cd ~/.ssh && ! cd " + dir + " && grep -r . .",
		"cd " + dir + " && (cd ~/.ssh && grep -r . .)",
		// RV26-1: a later step that goes back to an earlier directory.
		"cd ~/.ssh; cd /tmp && { cd -; grep -r . .; }",
		"cd ~/.ssh; cd /tmp && (cd -; grep -r . .)",
		"pushd ~/.ssh; cd /tmp && { popd; grep -r . .; }",
		"cd ~/.ssh; cd /tmp && { cd ~-; grep -r . .; }",
		"cd ~/.ssh; cd /tmp && { cd \"$OLDPWD\"; grep -r . .; }",
		"cd ~/.ssh && cd /tmp && if cd -; then grep -r . .; fi",
		"cd ~/.ssh && cd /tmp && for x in 1; do cd -; grep -r . .; done",
		"cd ~/.ssh; cd /tmp && { CDPATH=" + home + " cd .ssh; grep -r . .; }",
		"cd ~/.ssh; cd /tmp && { cd - >/dev/null; grep -r . .; }",
		"cd ~/.ssh; cd /tmp && (cd - && grep -r . .)",
		"cd ~/.ssh; cd /tmp && for x in 1 2; do grep -r . .; cd ~-; done",
		"back() { cd ~-; }; cd ~/.ssh; cd /tmp && { back; grep -r . .; }",
		"cd ~/.ssh; cd /tmp && { eval \"$GO\"; grep -r . .; }",
		// RV-it2-1: a directory program split across word parts, also
		// inside a nested shell body or a loop.
		"cd ~/.ssh; cd /tmp && { c''d -; grep -r . .; }",
		"cd ~/.ssh; cd /tmp && { c\\d -; grep -r . .; }",
		"cd ~/.ssh; cd /tmp && { \"c\"d -; grep -r . .; }",
		"cd ~/.ssh; cd /tmp && { c'd' -; grep -r . .; }",
		"pushd ~/.ssh; pushd /tmp && { p''opd; grep -r . .; }",
		"cd ~/.ssh; cd /tmp && bash -c 'c\"\"d -; grep -r . .'",
		"cd ~/.ssh; cd /tmp && bash -c $'c\\x64 -; grep -r . .'",
		"cd ~/.ssh; cd /tmp && for d in -; do c''d $d; grep -r . .; done",
		"cd ~/.ssh; cd /tmp && for d in -; do c''d $d; cat *; done",
		"cd ~/.ssh; cd /tmp && (c''d - && grep -r . .)",
		"cd ~/.ssh; cd /tmp && { {cd,} -; grep -r . .; }",
	} {
		if !posixShellPrivateKeyRead(command, cwd, home) {
			t.Errorf("posixShellPrivateKeyRead(%q) = false, want a key read", command)
		}
	}
}

func TestActionWindowsKeyReadAfterACertainLocationChange(t *testing.T) {
	const home, cwd = `C:\Users\u`, `C:\Users\u\proj`
	for _, command := range []string{
		"cd ~/.ssh && cd /c/Users/u/proj && grep -rn TODO .",
		`cd C:\Users\u\.ssh && cd C:\Users\u\proj && grep -rn TODO .`,
		`Set-Location ~\.ssh && Set-Location D:\proj && grep -rn TODO .`,
	} {
		if ActionPrivateKeyRead(command, cwd, home) {
			t.Errorf("ActionPrivateKeyRead(%q) = true, want no key read", command)
		}
	}
	for _, command := range []string{
		"cd ~/.ssh; cd /c/nonexistent; grep -r . .",
		"cd /c/Users/u/proj && cd ~/.ssh && grep -r . .",
		"cd ~/.ssh && cd /c/Users/u/proj || grep -r . .",
		"cd ~/.ssh && cd - && grep -r . .",
		// cmd's cd without /d keeps the current drive.
		`cd C:\Users\u\.ssh && cd D:\proj && grep -r . .`,
		// RV26-1: a location change inside parentheses.
		"cd ~/.ssh; cd /c/tmp && (cd - && grep -r . .)",
		"cd ~/.ssh; cd /c/tmp && ( cd - && grep -r . . )",
		"pushd ~/.ssh; cd /c/tmp && (popd && grep -r . .)",
		"pushd ~/.ssh; cd /c/tmp; (grep -r . .)",
		`cd ~\.ssh; Set-Location C:\tmp && (Set-Location -) && Get-ChildItem -Recurse . | Select-String PRIVATE`,
	} {
		if !ActionPrivateKeyRead(command, cwd, home) {
			t.Errorf("ActionPrivateKeyRead(%q) = false, want a key read", command)
		}
	}
}
