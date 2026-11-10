// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// BoundCommandOperands is the reading of a shell command that the hook
// client and the gateway both judge when the call has more operands than
// actionfacts.MaxOperandsPerCall (GAP-0943, GAP-0963): over reports that, and
// reduced keeps the first operands, and of the later ones every word that is
// not a plain name (see plainOperandName), however many there are. The
// operands left out are plain names that no protected file is called by
// their text; whether such a name is a link to a protected file is not asked
// for them, so the caller treats the call as unresolved and its policy tier
// decides. Every word is matched as text; only the reads of the file system
// are bounded.
func BoundCommandOperands(command string) (reduced string, over bool) {
	return actionfacts.BoundOperands(command, plainOperandName)
}

// protectedNameParts are the parts of a name that keep it judged however
// plain it reads: the keys files and the folders that hold them, the state of
// DefenseClaw, the places the system and the user shell start programs from,
// and the agent instruction files (InstructionFileNames).
var protectedNameParts = [...]string{
	"key", "ssh", "authorized", "defenseclaw", "claw", "id_", "rsa", "ed25519", "ecdsa", "pem", "secret",
	"token", "credential", "passw", "shadow", "sudoers", "kube", "aws", "netrc", "pgpass", "env",
	"profile", "bashrc", "zshrc", "zshenv", "zlogin", "bash_", "cron", "systemd", "launch", "plist",
	"init.d", "rc.d", "rc.local", "startup", "sshd", "motd", "hook",
}

// protectedSystemRoots are the top folders whose files the system reads as
// its own settings, so that a path below one stays judged.
var protectedSystemRoots = [...]string{
	"etc", "root", "boot", "usr", "var", "lib", "lib64", "opt", "bin", "sbin", "proc", "sys", "dev", "private",
	"system", "library", "windows", "programdata",
}

// plainOperandName reports a word that no protected file is called by its
// text, and that is no form the readers expand: after one pair of plain
// quotes is taken off, a relative or absolute path (a drive letter allowed)
// of plain segments. A segment starts with no dot, has no dot-dot, variable,
// glob, home, brace, percent, stream or short-name form, no trailing dot, no
// protected name part, and is not an ssh control file; the path is not below
// a system folder and is no UNC form. Such a word can name a protected file
// only through a link in it, which the unresolved call does not ask about.
func plainOperandName(word string) bool {
	if len(word) >= 2 && (word[0] == 0x27 || word[0] == 0x22) && word[len(word)-1] == word[0] {
		word = word[1 : len(word)-1]
	}
	if word == "" || word[0] == 0x2d {
		return false
	}
	for i := 0; i < len(word); i++ {
		c := word[i]
		if !plainOperandByte(c, i) {
			return false
		}
	}
	path := strings.ReplaceAll(word, "\\", "/")
	if strings.HasPrefix(path, "//") {
		return false
	}
	drive := len(path) >= 2 && path[1] == 0x3a
	if drive && (len(path) < 3 || path[2] != 0x2f) {
		return false
	}
	lower := strings.ToLower(path)
	for _, part := range protectedNameParts {
		if strings.Contains(lower, part) {
			return false
		}
	}
	for _, name := range InstructionFileNames {
		if strings.Contains(lower, strings.ToLower(name)) {
			return false
		}
	}
	segments := strings.Split(lower, "/")
	if drive {
		segments = segments[1:]
	}
	if drive || strings.HasPrefix(path, "/") {
		// The top folder of an absolute path.
		top := ""
		for _, segment := range segments {
			if segment != "" {
				top = segment
				break
			}
		}
		if slices.Contains(protectedSystemRoots[:], top) {
			return false
		}
	}
	for _, segment := range segments {
		switch {
		case segment == "" || segment == ".":
		case strings.HasPrefix(segment, ".") || strings.HasSuffix(segment, "."):
			return false
		case sshControlName(segment):
			return false
		}
	}
	return true
}

// sshControlName reports a name of the files under ~/.ssh that sshd or ssh
// run or read as policy (SSHControlFiles) or that hold keys (AuthorizedKeysFiles).
func sshControlName(segment string) bool {
	return slices.Contains(SSHControlFiles[:], segment) || slices.Contains(AuthorizedKeysFiles[:], segment)
}

// plainOperandByte reports a byte a plain name is made of: a letter, a digit,
// one of _ . + @ , - / or a backslash, or the colon of a drive letter.
func plainOperandByte(c byte, i int) bool {
	switch {
	case c >= 0x30 && c <= 0x39, c >= 0x41 && c <= 0x5a, c >= 0x61 && c <= 0x7a:
		return true
	case strings.IndexByte("_.+@,-/\\", c) >= 0:
		return true
	}
	return c == 0x3a && i == 1
}
