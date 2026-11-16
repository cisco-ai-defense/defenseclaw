// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGAP0529POSIXCopyOptionVariableWindowsHome(t *testing.T) {
	home := "C:/Users/Alice"
	cwd := home + "/project"
	for _, row := range []struct {
		name, command string
		block         bool
	}{
		{"option variable", `t="-t $HOME/.ssh"; cp $t a.txt`, true},
		{"attached option variable", `t="--target-directory=$HOME/.ssh"; cp $t a.txt`, true},
		{"single parameter destination", `t="a.txt $HOME/.ssh"; cp $t`, true},
		{"single parameter option and source", `t="-t $HOME/.ssh a.txt"; cp $t`, true},
		{"literal option", `cp -t "$HOME/.ssh" a.txt`, true},
		{"ordinary directory", `t="-t $HOME/build"; cp $t a.txt`, false},
		{"ordinary single parameter destination", `t="a.txt $HOME/build"; cp $t`, false},
		{"ordinary single parameter option", `t="-t $HOME/build a.txt"; cp $t`, false},
		{"quoted option variable", `t="-t $HOME/.ssh"; cp "$t" a.txt`, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			got := actionPosixTargetMention(row.command, cwd, home, 0, false, nil)
			if got != row.block {
				t.Errorf("POSIX reading %t, want %t", got, row.block)
			}
		})
	}
}

func TestGAP0529POSIXCopyOptionVariableDefaultIFS(t *testing.T) {
	home := "C:/Users/Alice"
	cwd := home + "/project"
	for _, row := range []struct {
		name, separator string
		protected       bool
	}{
		{"space", " ", true},
		{"tab", "\t", true},
		{"newline", "\n", true},
		{"nonbreaking space", "\u00a0", false},
		{"em space", "\u2003", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			command := `t="-t` + row.separator + `$HOME/.ssh"; cp $t a.txt`
			mention := actionPosixTargetMention(command, cwd, home, 0, false, nil)
			decision := ActionCommandDecisionInShell(command, cwd, home, nil, true)
			if mention != row.protected || (decision == "protected-target") != row.protected {
				t.Errorf("mention=%t decision=%q, want protected=%t", mention, decision, row.protected)
			}
		})
	}
}

func TestGAP0529POSIXCopyDestinationVariableDefaultIFS(t *testing.T) {
	home := "C:/Users/Alice"
	cwd := home + "/project"
	for _, row := range []struct {
		name, separator string
		protected       bool
	}{
		{"leading space", " ", true},
		{"leading tab", "\t", true},
		{"nonbreaking space", "\u00a0", false},
		{"em space", "\u2003", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			command := `t="` + row.separator + `$HOME/.ssh"; cp a.txt $t`
			mention := actionPosixTargetMention(command, cwd, home, 0, false, nil)
			if mention != row.protected {
				t.Errorf("mention=%t, want protected=%t", mention, row.protected)
			}
		})
	}
}

func TestGAP0529CopyExpandedOperandRoles(t *testing.T) {
	home := "C:/Users/Alice"
	cwd := home + "/project"
	if runtime.GOOS != "windows" {
		home = t.TempDir()
		cwd = filepath.Join(home, "project")
		for _, dir := range []string{cwd, filepath.Join(home, ".ssh")} {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, row := range []struct {
		name, command string
		protected     bool
	}{
		{"destination leading space", `t=" $HOME/$p"; cp a.txt $t`, true},
		{"destination leading tab", "t=\"\t$HOME/$p\"; cp a.txt $t", true},
		{"destination leading newline", "t=\"\n$HOME/$p\"; cp a.txt $t", true},
		{"destination after end of options", `t=" $HOME/$p"; cp -- a.txt $t`, true},
		{"destination after option", `t=" $HOME/$p"; cp -v a.txt $t`, true},
		{"destination after extra source", `t=" extra.txt $HOME/$p"; cp a.txt $t`, true},
		{"one parameter holds both operands", `t="a.txt $HOME/$p"; cp $t`, true},
		{"one parameter holds option and operands", `t="-t $HOME/$p a.txt"; cp $t`, true},
		{"ordinary destination", `p=build; t=" $HOME/$p"; cp a.txt $t`, false},
		{"ordinary destination leading tab", "p=build; t=\"\t$HOME/$p\"; cp a.txt $t", false},
		{"ordinary two operands", `p=build; t="a.txt $HOME/$p"; cp $t`, false},
		{"ordinary option target", `p=build; t="-t $HOME/$p a.txt"; cp $t`, false},
		{"protected source", `t=" $HOME/$p"; cp $t build/`, false},
		{"protected source leading tab", "t=\"\t$HOME/$p\"; cp $t build/", false},
		{"quoted destination", `t=" $HOME/$p"; cp a.txt "$t"`, false},
		{"read-only print", `t=" $HOME/$p"; printf '%s\n' $t`, false},
		{"print to ordinary file", `t=" $HOME/$p"; printf '%s\n' $t > report.txt`, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			command := `p=ssh; p=".$p"; ` + row.command
			mention := actionPosixTargetMention(command, cwd, home, 0, false, nil)
			decision := ActionCommandDecisionInShell(command, cwd, home, nil, true)
			if mention != row.protected || (decision == "protected-target") != row.protected {
				t.Errorf("mention=%t decision=%q, want protected=%t", mention, decision, row.protected)
			}
		})
	}
}

func TestGAP0529ReadOnlyExpandedLinkData(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires Windows developer privileges")
	}
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	ssh := filepath.Join(home, ".ssh")
	for _, dir := range []string{cwd, ssh} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(ssh, "authorized_keys")
	if err := os.WriteFile(keys, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(keys, filepath.Join(cwd, "keylink")); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct{ name, command string }{
		{"link printf", `f=key; f="${f}link"; t=" $f"; printf '%s\n' $t > report.txt`},
		{"link echo", `f=key; f="${f}link"; t=" $f"; echo $t > report.txt`},
		{"link readonly printf", `f=key; f="${f}link"; t=" $f"; printf '%s\n' $t`},
		{"link readonly echo", `f=key; f="${f}link"; t=" $f"; echo $t`},
		{"link source", `f=key; f="${f}link"; t=" $f"; cp $t build/`},
		{"ordinary printf", `f=note; t=" $f"; printf '%s\n' $t > report.txt`},
	} {
		t.Run(row.name, func(t *testing.T) {
			if decision := ActionCommandDecisionInShell(row.command, cwd, home, nil, true); decision != "" {
				t.Errorf("decision=%q, want allow", decision)
			}
		})
	}
}
