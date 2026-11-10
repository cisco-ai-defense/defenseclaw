// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"regexp"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// BoundCommandOperands is the reading of a shell command that the hook
// client and the gateway both judge when a statement has more operands than
// actionfacts.MaxOperandsPerStatement (GAP-0943, GAP-0963): over reports
// that, and reduced keeps the first operands of each statement, every
// redirection, and the later operands that are not plain names (a path with
// a separator form, a variable, a glob, a hidden or parent folder, a quoted
// word) up to the same number again. The operands left out are plain names
// of the current folder or of folders below it that no protected file is
// called; whether such a name is a link to a protected file is not asked for
// them, so the caller treats the call as unresolved and its policy tier
// decides.
func BoundCommandOperands(command string) (reduced string, over bool) {
	return actionfacts.BoundOperands(command, plainOperandName)
}

// plainOperandPattern is a relative path of plain segments: each starts with
// a letter, a digit or an underscore, and has no dot-dot, variable, glob,
// quote, home or drive form.
var plainOperandPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.+@%,-]*(?:/[A-Za-z0-9_][A-Za-z0-9_.+@%,-]*)*$`)

// protectedNameParts are the parts of a name that stay judged however plain
// the name reads: the keys files and the folders that hold them, the state
// of DefenseClaw, and the agent instruction files (InstructionFileNames).
var protectedNameParts = [...]string{
	"key", "ssh", "authorized", "defenseclaw", "claw", "id_", "rsa", "ed25519", "ecdsa", "pem", "secret",
	"token", "credential", "passw", "shadow", "sudoers", "kube", "aws", "netrc", "pgpass", "env",
}

func plainOperandName(word string) bool {
	if !plainOperandPattern.MatchString(word) {
		return false
	}
	lower := strings.ToLower(word)
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
	// Windows reads a name that ends in a dot as the name without it.
	return !strings.HasSuffix(word, ".")
}
