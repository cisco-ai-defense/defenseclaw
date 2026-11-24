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
// POSIX script rules read it. Any other command gives "".
func windowsHookScriptCommandAsPOSIX(command string) string {
	word, rest, ok := windowsHookCommandWord(command)
	if !ok {
		return ""
	}
	posix, ok := windowsAbsolutePathAsPOSIX(word)
	if !ok {
		return ""
	}
	return posixHookCommandWord(posix) + rest
}

// windowsHookCommandWord splits a hook command into its first word, as
// written, bare or in single or double quotes, and the rest. A double-quoted
// word with a $ or a backquote is not a path: the shell would expand it.
func windowsHookCommandWord(command string) (word, rest string, ok bool) {
	command = strings.TrimSpace(command)
	if quoted, isQuoted := strings.CutPrefix(command, `"`); isQuoted {
		end := strings.IndexByte(quoted, '"')
		if end < 0 || strings.ContainsAny(quoted[:end], "$`") {
			return "", "", false
		}
		word, rest = quoted[:end], quoted[end+1:]
		if rest != "" && rest[0] != ' ' && rest[0] != '\t' {
			return "", "", false
		}
		return word, rest, true
	}
	return posixHookCommandSplit(command)
}

// windowsAbsolutePathAsPOSIX returns a Windows absolute path without its
// volume, with forward slashes and in lower case (Windows file names are case
// insensitive): C:\a\b and C:/a\b give /a/b, \\server\share\a gives /a, and
// the \\?\ and \\.\ forms of either give the same. Under \\?\ and \\.\ a
// forward slash is part of a name, not a separator, so such a path is
// refused, as is a drive-relative (C:a) or volume-less (\a) path. The path is
// not cleaned and its volume is dropped: a rule that decides whether a path
// lies in a folder compares windowsResolvedPath instead.
func windowsAbsolutePathAsPOSIX(name string) (string, bool) {
	_, posix, _, ok := windowsAbsolutePathParts(name)
	return posix, ok
}

// windowsAbsolutePathParts splits a Windows absolute path, read as
// windowsAbsolutePathAsPOSIX reads it, into its volume in lower case (c: for
// a drive, //server/share for a UNC path, either under \\?\ or \\.\ too) and
// the POSIX form of the rest, and reports a \\?\ or \\.\ prefix.
func windowsAbsolutePathParts(name string) (volume, posix string, verbatim, ok bool) {
	if strings.ContainsAny(name, "\x00\r\n") {
		return "", "", false, false
	}
	for _, prefix := range []string{`\\?\`, `\\.\`} {
		if rest, found := strings.CutPrefix(name, prefix); found {
			if strings.Contains(rest, "/") {
				return "", "", false, false
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
		volume, name = name[:2], name[2:]
	case strings.HasPrefix(name, "//"):
		parts := strings.SplitN(name[2:], "/", 3)
		if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
			return "", "", false, false
		}
		volume, name = "//"+parts[0]+"/"+parts[1], "/"+parts[2]
	default:
		return "", "", false, false
	}
	return strings.ToLower(volume), strings.ToLower(name), verbatim, true
}

// windowsResolvedPath returns a Windows absolute path as Windows resolves it,
// read as text and never opened: its volume (windowsAbsolutePathParts) and
// its cleaned POSIX form on that volume, both in lower case. A . or ..
// segment is resolved as Windows resolves it, except under \\?\ or \\.\,
// where the name goes to the file system as written, so such a path is
// refused, as is one with an empty segment there. A segment that ends in a
// dot or a space is refused too: Windows drops those, so "hooks." is
// "hooks" and ".. " is "..". A refused path lies in no folder.
func windowsResolvedPath(name string) (volume, posix string, ok bool) {
	volume, posix, verbatim, ok := windowsAbsolutePathParts(name)
	if !ok {
		return "", "", false
	}
	for _, segment := range strings.Split(strings.TrimPrefix(posix, "/"), "/") {
		switch {
		case segment == "." || segment == "..":
			if verbatim {
				return "", "", false
			}
		case segment == "":
			if verbatim && posix != "/" {
				return "", "", false
			}
		case strings.HasSuffix(segment, ".") || strings.HasSuffix(segment, " "):
			return "", "", false
		}
	}
	return volume, path.Clean(posix), true
}

// windowsHookCommandInDir returns the path, relative to dir, of a hook
// command's first word when that word is a Windows absolute path inside dir:
// both resolved (windowsResolvedPath) and on the same volume, in any case and
// with either separator. dir is a windowsResolvedPath volume and path.
func windowsHookCommandInDir(command, volume, dir string) (string, bool) {
	word, _, ok := windowsHookCommandWord(command)
	if !ok {
		return "", false
	}
	wordVolume, wordPath, ok := windowsResolvedPath(word)
	if !ok || wordVolume != volume {
		return "", false
	}
	name, found := strings.CutPrefix(wordPath, strings.TrimSuffix(dir, "/")+"/")
	return name, found && name != ""
}

// hookCommandInWindowsDir reports whether command's first word is a Windows
// path inside dir, a Windows path too (windowsHookCommandInDir): on dir's
// volume, after . and .. are resolved, in any case and with either
// separator. On a Windows host the hooks dir is a backslash path, so the
// hooks-dir claim never matched a handler there and Setup kept one the doctor
// reported, then failed its final check (GAP-1981). The same folder on
// another drive or share, or a path that leaves it through .., is the user's,
// as in 1.0.10 (GAP-2116).
func hookCommandInWindowsDir(command, dir string) bool {
	volume, dirPath, ok := windowsResolvedPath(dir)
	if !ok {
		return false
	}
	_, found := windowsHookCommandInDir(command, volume, dirPath)
	return found
}
