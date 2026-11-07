// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"net/netip"
	"os"
	"path"
	"strings"
	"sync"
)

// managedAgentSettingsDirs are the vendor machine-policy directories on
// Linux and macOS that DefenseClaw publishes an agent's managed settings
// into (Claude Code managed-settings.json and managed-settings.d, Codex
// requirements.toml, the Cursor, Copilot and OpenCode managed policy
// files). The list is the one internal/enterpriseunix writes to; the
// operating system refuses an agent that is not root, so the hook names the
// attempt before the refusal.
var managedAgentSettingsDirs = []string{
	"/etc/claude-code",
	"/Library/Application Support/ClaudeCode",
	"/etc/codex",
	"/etc/cursor",
	"/Library/Application Support/Cursor",
	"/etc/github-copilot",
	"/etc/opencode",
	"/Library/Application Support/opencode",
}

// ManagedAgentSettingsPath reports a clean absolute POSIX path that is one
// of the managed agent settings directories, or below one
// (rel-1-0-6:GAP-0734). The macOS directory names are matched in any case,
// as that file system is case-insensitive, and /etc is read as its
// canonical /private/etc there (the path the Codex connector reads).
func ManagedAgentSettingsPath(value string) bool {
	value = strings.TrimRight(value, "/")
	if rest, ok := strings.CutPrefix(value, "/private/etc/"); ok {
		value = "/etc/" + rest
	}
	for _, dir := range managedAgentSettingsDirs {
		same := func(a, b string) bool { return a == b }
		if strings.HasPrefix(dir, "/Library/") {
			same = strings.EqualFold
		}
		if len(value) >= len(dir) && same(value[:len(dir)], dir) && (len(value) == len(dir) || value[len(dir)] == '/') {
			return true
		}
	}
	return false
}

// windowsManagedAgentSettingsDirs are the machine-policy directories on
// Windows that DefenseClaw publishes an agent's managed settings into, below
// the Program Files and ProgramData roots (internal/enterprisepolicy
// paths.go), lower case, one entry per directory name after the drive.
var windowsManagedAgentSettingsDirs = [][]string{
	{"program files", "claudecode"},
	{"programdata", "openai", "codex"},
	{"programdata", "cursor"},
	{"programdata", "github", "copilot"},
	{"programdata", "opencode"},
}

// WindowsManagedAgentSettingsPath reports a Windows path that is one of the
// managed agent settings directories, or below one, on any drive and in any
// case, in any spelling of the local volume (WindowsLocalDrivePath) and
// with 8.3 short names for the directories (rel-1-0-6:GAP-0734).
func WindowsManagedAgentSettingsPath(value string) bool {
	drive, ok := WindowsLocalDrivePath(value)
	if !ok {
		return false
	}
	parts := strings.Split(strings.Trim(path.Clean(drive[2:]), "/"), "/")
	for _, names := range windowsManagedAgentSettingsDirs {
		if len(parts) >= len(names) && windowsNamesMatch(parts[:len(names)], names) {
			return true
		}
	}
	return false
}

// windowsNamesMatch reports each part as the lower-case long name of the
// same position, or an 8.3 short name of it.
func windowsNamesMatch(parts, names []string) bool {
	for i, name := range names {
		part := strings.ToLower(strings.TrimRight(parts[i], ". "))
		if part != name && !windowsShortNameOf(part, name) {
			return false
		}
	}
	return true
}

// windowsShortNameOf reports the 8.3 short name stem~N of a long name: up to
// six characters of the long name without its spaces and dots, a tilde and
// a number (PROGRA~1 is Program Files).
func windowsShortNameOf(short, long string) bool {
	tilde := strings.LastIndexByte(short, '~')
	if tilde < 1 || tilde > 6 || tilde == len(short)-1 {
		return false
	}
	for _, digit := range []byte(short[tilde+1:]) {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return strings.HasPrefix(strings.NewReplacer(" ", "", ".", "").Replace(long), short[:tilde])
}

// WindowsLocalDrivePath returns the drive path ("C:/dir/file", slash
// separated) that a Windows path names on this machine, or false when it
// names no local volume: the drive path itself, the \\?\ and \\.\ prefixes
// of it, and the administrative share of a drive on the local machine
// (\\localhost\C$\dir, \\127.0.0.1\C$\dir, \\<this host>\C$\dir, with or
// without the \\?\UNC\ prefix). The same file has all of these names, so a
// check of protected state matches the one the volume holds
// (rel-1-0-6:GAP-0729, GAP-0734).
func WindowsLocalDrivePath(value string) (string, bool) {
	slashed := strings.ReplaceAll(value, `\`, "/")
	for _, prefix := range []string{"//?/", "//./"} {
		if rest, ok := strings.CutPrefix(slashed, prefix); ok {
			slashed = rest
			if len(rest) >= 4 && strings.EqualFold(rest[:4], "unc/") {
				slashed = "//" + rest[4:]
			}
			break
		}
	}
	if len(slashed) >= 3 && isASCIILetter(slashed[0]) && slashed[1] == ':' && slashed[2] == '/' {
		return strings.ToUpper(slashed[:1]) + slashed[1:], true
	}
	rest, ok := strings.CutPrefix(slashed, "//")
	if !ok {
		return "", false
	}
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) < 2 || len(parts[1]) != 2 || !isASCIILetter(parts[1][0]) || parts[1][1] != '$' ||
		!windowsLocalHost(parts[0]) {
		return "", false
	}
	tail := ""
	if len(parts) == 3 {
		tail = parts[2]
	}
	return strings.ToUpper(parts[1][:1]) + ":/" + tail, true
}

// windowsLocalHost reports a UNC host name that is this machine: localhost,
// a loopback address in any spelling Windows resolves (127.0.0.0/8, ::1,
// the ipv6-literal.net form), or the host's own name.
func windowsLocalHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	switch host {
	case "localhost", "localhost.localdomain", "--1.ipv6-literal.net", "0--1.ipv6-literal.net":
		return true
	}
	if address, err := netip.ParseAddr(host); err == nil {
		return address.IsLoopback()
	}
	name, _, _ := strings.Cut(localHostName(), ".")
	short, _, _ := strings.Cut(host, ".")
	return name != "" && short == name
}

var localHostName = sync.OnceValue(func() string {
	name, _ := os.Hostname()
	return strings.ToLower(name)
})
