// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"path"
	"slices"
	"strings"
)

// hookUsesForeignDefenseClawClaudeCodeScript recognizes a handler that runs
// a DefenseClaw Claude Code hook Setup did not write at this path: the
// generated hook of another DefenseClaw data dir (a settings.json copied from
// another account or from dotfiles, whose script is often unreadable, so the
// marker check cannot claim it; GAP-2031), or this install's handler after
// its script path was edited by hand. A handler that still carries the exact
// generated missing-script guard is DefenseClaw's whatever its path.
// Setup then kept the dead entries next to its own and the edited one kept
// failing every call (GAP-0907). The script may be named by a POSIX or a
// Windows path, and the handler may be another account's Windows native
// registration (claudeCodeForeignNativeHook); both are recognized on every
// OS (GAP-1909). Only Setup's and Teardown's removal pass uses this, with the
// handler as written, not its exec view.
func hookUsesForeignDefenseClawClaudeCodeScript(rawHook interface{}) bool {
	hook, ok := rawHook.(map[string]interface{})
	if !ok {
		return false
	}
	if claudeCodeForeignNativeHook(hook) {
		return true
	}
	command, _ := hook["command"].(string)
	unguarded := claudeCodeUnguardedHookCommand(command)
	if unguarded != command {
		return true
	}
	rest, edited := editedDefenseClawHookScript(unguarded, "claude-code-hook.sh")
	if !edited {
		rest, edited = editedDefenseClawHookScript(windowsHookScriptCommandAsPOSIX(unguarded), "claude-code-hook.sh")
	}
	return edited && rest == ""
}

// claudeCodeForeignNativeHook reports a Windows Claude Code handler that
// DefenseClaw Setup writes, whichever account or install folder it names: one
// of the exact generated guard forms (claudeCodeLauncherGuardParts renders the
// whole argv again and compares it), or the exec form at a one-line install's
// <profile>\.local\bin\defenseclaw-hook.exe. Either must run an absolute
// defenseclaw-hook.exe with DefenseClaw's Claude Code hook argv. A settings.json
// copied from another Windows account kept that account's guards, which block
// every call when its launcher cannot be read, and Setup could not repair them
// (GAP-1909). The exec form in any other folder stays: a matching basename is
// not ownership (TestClaudeCode_SetupPreservesForeignSameBasenameExecHook).
func claudeCodeForeignNativeHook(hook map[string]interface{}) bool {
	if kind, present := hook["type"]; present && kind != "command" {
		return false
	}
	launcher, hookArgs, guarded := claudeCodeLauncherGuardParts(hook)
	if !guarded {
		launcher, _ = hook["command"].(string)
		var ok bool
		if hookArgs, ok = claudeCodeNativeExecArguments(hook); !ok || !claudeCodeOneLineLauncherPath(launcher) {
			return false
		}
	}
	return claudeCodeAbsoluteHookExecutable(launcher) && claudeCodeDefenseClawHookArgs(hookArgs)
}

// claudeCodeDefenseClawHookArgs reports DefenseClaw's Claude Code hook argv,
// per-user or managed.
func claudeCodeDefenseClawHookArgs(args []string) bool {
	return slices.Equal(args, []string{"hook", "--connector", "claudecode"}) ||
		slices.Equal(args, []string{"hook", "--connector", "claudecode", "--enterprise-managed"})
}

// claudeCodeOneLineLauncherPath reports a Windows absolute, clean path to
// defenseclaw-hook.exe in a .local\bin folder under some directory, the
// one-line install's launcher of any account.
func claudeCodeOneLineLauncherPath(launcher string) bool {
	posix, ok := windowsAbsolutePathAsPOSIX(launcher)
	if !ok || path.Clean(posix) != posix {
		return false
	}
	account, found := strings.CutSuffix(posix, "/.local/bin/"+strings.ToLower(windowsHookBinaryName))
	return found && account != ""
}

// windowsHookScriptCommandAsPOSIX rewrites a hook command whose first word is
// a Windows absolute path (windowsAbsolutePathAsPOSIX), bare or in single or
// double quotes, as the same command with that path in POSIX form, so the
// POSIX script rules read it. Any other command gives "". A double-quoted word
// with a $ or a backquote is not a path: the shell would expand it.
func windowsHookScriptCommandAsPOSIX(command string) string {
	command = strings.TrimSpace(command)
	var word, rest string
	if quoted, ok := strings.CutPrefix(command, `"`); ok {
		end := strings.IndexByte(quoted, '"')
		if end < 0 || strings.ContainsAny(quoted[:end], "$`") {
			return ""
		}
		word, rest = quoted[:end], quoted[end+1:]
		if rest != "" && rest[0] != ' ' && rest[0] != '\t' {
			return ""
		}
	} else if word, rest, ok = posixHookCommandSplit(command); !ok {
		return ""
	}
	posix, ok := windowsAbsolutePathAsPOSIX(word)
	if !ok {
		return ""
	}
	return posixHookCommandWord(posix) + rest
}

// windowsAbsolutePathAsPOSIX returns a Windows absolute path without its
// volume, with forward slashes and in lower case (Windows file names are case
// insensitive): C:\a\b and C:/a\b give /a/b, \\server\share\a gives /a, and
// the \\?\ and \\.\ forms of either give the same. Under \\?\ and \\.\ a
// forward slash is part of a name, not a separator, so such a path is
// refused, as is a drive-relative (C:a) or volume-less (\a) path.
func windowsAbsolutePathAsPOSIX(name string) (string, bool) {
	if strings.ContainsAny(name, "\x00\r\n") {
		return "", false
	}
	verbatim := false
	for _, prefix := range []string{`\\?\`, `\\.\`} {
		if rest, ok := strings.CutPrefix(name, prefix); ok {
			if strings.Contains(rest, "/") {
				return "", false
			}
			name, verbatim = rest, true
			break
		}
	}
	name = strings.ReplaceAll(name, `\`, "/")
	if verbatim && len(name) > 4 && strings.EqualFold(name[:4], "UNC/") {
		name = "//" + name[4:]
	}
	switch {
	case isWindowsDriveAbsolutePath(name):
		name = name[2:]
	case strings.HasPrefix(name, "//"):
		parts := strings.SplitN(name[2:], "/", 3)
		if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
			return "", false
		}
		name = "/" + parts[2]
	default:
		return "", false
	}
	return strings.ToLower(name), true
}
