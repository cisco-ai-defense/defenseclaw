// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

// shellStartupHomeNames are the files directly in an account's home that a
// login or an interactive shell reads at its start (bash, POSIX sh and zsh).
// It is the single table: the persistence rule, the protected-set builder and
// the archive-landing check read it, so a startup file one of them knows is
// known to all (rel-1-0-10, Phase-1 tune side: .bash_aliases and .zshenv were
// in two of the three copies only).
var shellStartupHomeNames = [...]string{
	".bashrc", ".bash_profile", ".bash_login", ".bash_aliases", ".profile",
	".zshenv", ".zprofile", ".zshrc", ".zlogin",
}

// shellStartupSystemPaths are the system-wide copies, read for every account.
var shellStartupSystemPaths = [...]string{
	"/etc/profile", "/etc/bashrc", "/etc/bash.bashrc",
	"/etc/zshenv", "/etc/zsh/zshenv", "/etc/zprofile", "/etc/zsh/zprofile",
	"/etc/zshrc", "/etc/zsh/zshrc", "/etc/zlogin", "/etc/zsh/zlogin",
}

// ShellStartupHomeNames returns the names of the shell startup files that sit
// directly in a home.
func ShellStartupHomeNames() []string {
	return append([]string(nil), shellStartupHomeNames[:]...)
}

// ShellStartupSystemPaths returns the system-wide shell startup files, as
// fixed absolute POSIX paths. The scripts of /etc/profile.d are not in the
// table: the persistence rule reads the system profile exactly
// (TestSystemShellProfileOwnerIsExact), and the LD_PRELOAD fragment under
// /etc/profile.d has its own rule (global_ld_preload_profile.go).
func ShellStartupSystemPaths() []string {
	return append([]string(nil), shellStartupSystemPaths[:]...)
}

// ShellStartupHomeFile reports whether name is the file name of a shell
// startup file that sits directly in a home.
func ShellStartupHomeFile(name string) bool {
	for _, known := range shellStartupHomeNames {
		if name == known {
			return true
		}
	}
	return false
}
