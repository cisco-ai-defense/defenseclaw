// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"testing"
)

func TestShellStartupFileTable(t *testing.T) {
	for _, name := range []string{".bashrc", ".bash_profile", ".bash_login", ".bash_aliases", ".profile", ".zshenv", ".zprofile", ".zshrc", ".zlogin"} {
		if !ShellStartupHomeFile(name) {
			t.Errorf("%s is a shell startup file", name)
		}
		if !slices.Contains(ShellStartupHomeNames(), name) {
			t.Errorf("%s missing from the exported names", name)
		}
	}
	for _, name := range []string{".bashrc.example", "bashrc", ".bash_history", ".gitconfig", ""} {
		if ShellStartupHomeFile(name) {
			t.Errorf("%q is no shell startup file", name)
		}
	}
	for _, path := range []string{"/etc/profile", "/etc/bash.bashrc", "/etc/zsh/zshrc"} {
		if !ShellStartupSystemFile(path) {
			t.Errorf("%s is a system shell startup file", path)
		}
	}
	for _, path := range []string{"/etc/profile.d/x.sh", "/etc/profile.d/", "/etc/profilex", "/var/etc/profile", "/home/a/etc/profile.d/x.sh", "/etc/passwd"} {
		if ShellStartupSystemFile(path) {
			t.Errorf("%s is no system shell startup file", path)
		}
	}
	// The returned slices are copies: a caller cannot edit the table.
	names := ShellStartupHomeNames()
	names[0] = "x"
	if ShellStartupHomeNames()[0] == "x" {
		t.Error("the table was edited through a returned slice")
	}
}
