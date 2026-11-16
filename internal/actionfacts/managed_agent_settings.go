// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"net/netip"
	"os"
	"path"
	"runtime"
	"slices"
	"strings"
	"sync"
)

// managedSettingsDir is a vendor machine-policy directory and the entries
// directly under it that DefenseClaw publishes (a file, or a drop-in
// directory with everything below it), lower case. The directory itself is
// protected as a whole, since deleting or moving it removes the policy; any
// other name below it is an ordinary file that happens to sit in the vendor
// folder (rel-1-0-6:GAP-0734 review 9 M2).
type managedSettingsDir struct {
	dir     string
	entries []string
}

// The entries below are the files internal/enterprisepolicy writes
// (paths.go, claude.go, cursor.go, copilot.go, opencode.go, codex.go).
var (
	claudeManagedEntries   = []string{"managed-settings.json", "managed-settings.d"}
	codexManagedEntries    = []string{"requirements.toml"}
	cursorManagedEntries   = []string{"hooks.json", "defenseclaw-hook.ps1"}
	copilotManagedEntries  = []string{"policy.d"}
	opencodeManagedEntries = []string{"opencode.json", "opencode.jsonc"}
)

// managedAgentSettingsDirs are the vendor machine-policy directories on
// Linux and macOS that DefenseClaw publishes an agent's managed settings
// into (Claude Code managed-settings.json and managed-settings.d, Codex
// requirements.toml, the Cursor, Copilot and OpenCode managed policy
// files). The list is the one internal/enterpriseunix writes to; the
// operating system refuses an agent that is not root, so the hook names the
// attempt before the refusal.
var managedAgentSettingsDirs = []managedSettingsDir{
	{"/etc/claude-code", claudeManagedEntries},
	{"/Library/Application Support/ClaudeCode", claudeManagedEntries},
	{"/etc/codex", codexManagedEntries},
	{"/etc/cursor", cursorManagedEntries},
	{"/Library/Application Support/Cursor", cursorManagedEntries},
	{"/etc/github-copilot", copilotManagedEntries},
	{"/etc/opencode", opencodeManagedEntries},
	{"/Library/Application Support/opencode", opencodeManagedEntries},
}

// CaseInsensitiveFilesystem reports a host whose default file system ignores
// case: macOS. The platform this process runs on decides, never the spelling
// of a home or a path: a Linux host that has a /Users directory still tells
// two names that differ in case apart (rel-1-0-6:GAP-0734 review 11 M2).
func CaseInsensitiveFilesystem() bool {
	return runtime.GOOS == "darwin"
}

// ManagedAgentSettingsPath reports an absolute POSIX path that is one of
// the managed agent settings directories, or a published settings file or
// drop-in directory in one, or below one (rel-1-0-6:GAP-0734). Another
// file in the same vendor folder is an ordinary file. Names match exactly,
// since a Linux file system tells a name from its case variants; with
// caseFold (macOS, CaseInsensitiveFilesystem) they match in any case, and
// /etc is read as its canonical /private/etc (the path the Codex connector
// reads).
func ManagedAgentSettingsPath(value string, caseFold bool) bool {
	if !strings.HasPrefix(value, "/") {
		return false
	}
	value = path.Clean(value)
	if caseFold {
		value = strings.ToLower(value)
		if rest, ok := strings.CutPrefix(value, "/private/etc/"); ok {
			value = "/etc/" + rest
		}
	}
	for _, managed := range managedAgentSettingsDirs {
		dir := managed.dir
		if caseFold {
			dir = strings.ToLower(dir)
		}
		if !strings.HasPrefix(value, dir) {
			continue
		}
		if len(value) == len(dir) {
			return true
		}
		if value[len(dir)] != '/' {
			continue
		}
		entry, _, _ := strings.Cut(value[len(dir)+1:], "/")
		if slices.Contains(managed.entries, entry) {
			return true
		}
	}
	return false
}

// windowsManagedSettingsDir is managedSettingsDir for Windows: the
// directory names after the drive, lower case, and the entries below it.
type windowsManagedSettingsDir struct {
	names   []string
	entries []string
}

// windowsManagedAgentSettingsDirs are the machine-policy directories on
// Windows that DefenseClaw publishes an agent's managed settings into, below
// the Program Files and ProgramData roots (internal/enterprisepolicy
// paths.go).
var windowsManagedAgentSettingsDirs = []windowsManagedSettingsDir{
	{[]string{"program files", "claudecode"}, claudeManagedEntries},
	{[]string{"programdata", "openai", "codex"}, codexManagedEntries},
	{[]string{"programdata", "cursor"}, cursorManagedEntries},
	{[]string{"programdata", "github", "copilot"}, copilotManagedEntries},
	{[]string{"programdata", "opencode"}, opencodeManagedEntries},
}

// WindowsManagedAgentSettingsPath reports a Windows path that is one of the
// managed agent settings directories, or a published settings file or
// drop-in directory in one, or below one, on any drive and in any case, in
// any spelling of the local volume (WindowsLocalDrivePath) and with 8.3
// short names for the directories and files (rel-1-0-6:GAP-0734). Another
// file in the same vendor folder is an ordinary file.
func WindowsManagedAgentSettingsPath(value string) bool {
	drive, ok := WindowsLocalDrivePath(value)
	if !ok {
		return false
	}
	drive = path.Clean(drive)
	parts := strings.Split(strings.Trim(drive[2:], "/"), "/")
	// The shape of a short name does not say which file it is, or whether
	// the volume makes short names at all: where the path exists, the
	// operating system gives its long form and that decides, by exact name.
	aliases := true
	if slices.ContainsFunc(parts, windowsShortNameShaped) {
		if long, ok := windowsLongPath(drive); ok {
			parts, aliases = strings.Split(strings.Trim(long[2:], "/"), "/"), false
		}
	}
	for _, managed := range windowsManagedAgentSettingsDirs {
		count := len(managed.names)
		if len(parts) < count || !windowsNamesMatch(parts[:count], managed.names, aliases) {
			continue
		}
		if len(parts) == count {
			return true
		}
		for _, entry := range managed.entries {
			if windowsNameIs(parts[count], entry, aliases) {
				return true
			}
		}
	}
	return false
}

// windowsLongPath is the long form of a drive path ("C:/dir/file") on the
// volume this process runs on (GetLongPathName for the part that exists),
// or false when the operating system cannot say. It is a variable so that
// a test can stand in for a volume.
var windowsLongPath = osWindowsLongPath

// windowsNamesMatch reports each part as the lower-case long name of the
// same position, or, with aliases, an 8.3 short name of it.
func windowsNamesMatch(parts, names []string, aliases bool) bool {
	for i, name := range names {
		if !windowsNameIs(parts[i], name, aliases) {
			return false
		}
	}
	return true
}

// windowsNameIs reports a path part as a lower-case long name or, with
// aliases, an 8.3 short name of it. Windows ignores trailing dots and
// spaces.
func windowsNameIs(part, name string, aliases bool) bool {
	part = strings.ToLower(strings.TrimRight(part, ". "))
	return part == name || aliases && windowsShortNameOf(part, name)
}

// windowsShortNameShaped reports a path part with the tilde and digit of a
// short name, the only parts whose long form can differ.
func windowsShortNameShaped(part string) bool {
	tilde := strings.LastIndexByte(part, '~')
	return tilde > 0 && tilde+1 < len(part) && part[tilde+1] >= '0' && part[tilde+1] <= '9'
}

// windowsShortNameOf reports the 8.3 short name stem~N.EXT of a long name,
// as NTFS generates it, for a long name that needs one: the name is not
// already 8.3 (a directory named Codex or Cursor has no other name). The
// stem is the first six characters of the long name without its spaces and
// dots, N is 1 to 4 (PROGRA~1 is Program Files, MANAGE~1.JSO is
// managed-settings.json); from the fifth name with the same stem the stem is
// the first two characters and four hexadecimal digits of a hash, and N
// counts from 1 again (N 1 to 9 here). The shape only says which long name
// a short name would have; where the path exists the operating system gives
// the file (windowsLongPath), and a shape that the generator does not
// produce (P~1, PROG~1, PROGRA~5, name~0) is an ordinary name.
func windowsShortNameOf(short, long string) bool {
	longBase, longExt := splitWindowsExtension(long)
	if windowsName83(longBase, longExt) {
		return false
	}
	shortBase, shortExt := splitWindowsExtension(short)
	if shortExt != longExt[:min(3, len(longExt))] {
		return false
	}
	tilde := strings.LastIndexByte(shortBase, '~')
	if tilde < 1 || tilde != len(shortBase)-2 || shortBase[tilde+1] < '1' || shortBase[tilde+1] > '9' {
		return false
	}
	number := shortBase[tilde+1] - '0'
	stem := shortBase[:tilde]
	stripped := strings.NewReplacer(" ", "", ".", "").Replace(longBase)
	if number <= 4 && stem == stripped[:min(6, len(stripped))] {
		return true
	}
	if len(stem) != 6 || len(stripped) <= 6 || stem[:2] != stripped[:2] {
		return false
	}
	for _, digit := range []byte(stem[2:]) {
		if (digit < '0' || digit > '9') && (digit < 'a' || digit > 'f') {
			return false
		}
	}
	return true
}

// windowsName83 reports a name that is already a valid 8.3 name: a base of
// at most eight characters and an extension of at most three, with no space
// or other dot.
func windowsName83(base, ext string) bool {
	return len(base) <= 8 && len(ext) <= 3 && !strings.ContainsAny(base+ext, " .+,;=[]")
}

// splitWindowsExtension splits a name at its last dot.
func splitWindowsExtension(name string) (string, string) {
	if dot := strings.LastIndexByte(name, '.'); dot > 0 {
		return name[:dot], name[dot+1:]
	}
	return name, ""
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
// the ipv6-literal.net form), or one of the names of this host
// (localHostNames). A name that only shares the first label with this host,
// such as the same short name in another DNS domain, is another machine
// (rel-1-0-6:GAP-0734 review 11 M1).
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
	return host != "" && slices.Contains(localHostNames(), host)
}

// localHostNames are the names this machine answers to as a UNC server, lower
// case and without a trailing dot: the host name the operating system gives,
// its DNS fully qualified name where the platform has one, and the first
// label of each (the short name). It is a variable so that a test can stand
// in for a host.
var localHostNames = sync.OnceValue(func() []string {
	var names []string
	if name, err := os.Hostname(); err == nil {
		names = append(names, name)
	}
	names = append(names, osDNSHostName()...)
	var all []string
	for _, name := range names {
		name = strings.ToLower(strings.TrimSuffix(name, "."))
		if name == "" {
			continue
		}
		short, _, _ := strings.Cut(name, ".")
		all = append(all, name, short)
	}
	return all
})
