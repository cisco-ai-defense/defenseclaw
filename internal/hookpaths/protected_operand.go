// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"slices"
	"strings"
)

// ProtectedOperandName reports an operand that names a protected file by its
// last components: an authorized-keys file, the SSH folder, an SSH control
// file or private key below it, a shell startup profile, the Git hooks
// folder, and, with state, the DefenseClaw state folder (the target of a
// link). It reads the operand only: a comment or a data word of the call is
// never passed here.
func ProtectedOperandName(operand string, state bool) bool {
	operand = strings.ToLower(strings.NewReplacer("\\", "/", "\x27", "", "\"", "").Replace(operand))
	parts := strings.FieldsFunc(operand, func(r rune) bool { return r == rune(0x2f) })
	if len(parts) == 0 {
		return false
	}
	base := parts[len(parts)-1]
	parent := ""
	if len(parts) > 1 {
		parent = parts[len(parts)-2]
	}
	switch {
	case strings.HasPrefix(base, "authorized_keys"), strings.Contains(base, "administrators_authorized_keys"):
		return true
	case base == ".ssh", parent == ".ssh" && (slices.Contains(SSHControlFiles[:], base) || strings.HasPrefix(base, "id_")):
		return true
	case parent == ".git" && base == "hooks", parent == "hooks" && len(parts) > 2 && parts[len(parts)-3] == ".git", base == "hookspath":
		return true
	case slices.Contains(shellStartupNames, base), strings.Contains(base, "powershell_profile"):
		return true
	}
	return state && slices.Contains(parts, ".defenseclaw")
}

// shellStartupNames are the shell startup profiles of the user.
var shellStartupNames = []string{
	".bashrc", ".bash_profile", ".bash_login", ".zshrc", ".zprofile", ".zshenv", ".zlogin", ".profile",
	"config.fish", "profile.ps1", "profile",
}
