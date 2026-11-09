// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net"
	"os"
	"regexp"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// A Windows path names a file in more spellings than the path rules write:
// an 8.3 short name, a name with trailing dots or spaces, an alternate data
// stream, an extended-length prefix, the admin share of the local machine.
// All of them open the same file, so a protected file must get its verdict
// from the name Windows opens, not from the spelling the caller chose.
// windowsOpenedPath is that one reading, applied before the path rules and
// the semantic path proof read a Windows operand. Letter case is left to the
// callers, which already compare names as Windows does (windowsNameFold).

// expandWindowsShortNames is the file system's long-name form of a
// drive-letter path in forward-slash spelling: each 8.3 short name replaced
// by the name it stands for. A part that does not exist is left as written.
// The Windows build asks the file system; other builds and tests replace it.
var expandWindowsShortNames = osExpandWindowsShortNames

// windowsLocalHostname is the name of this machine, which names its own admin
// shares like localhost does. A variable so a test can name the machine.
var windowsLocalHostname = os.Hostname

// windowsAccountWord is an account folder name the path rules can read: the
// rules write the account of a home as \w+.
var windowsAccountWord = regexp.MustCompile(`^\w+$`)

// windowsOpenedPath returns the path Windows opens for a Windows operand
// spelling, in forward-slash spelling, or false when the spelling is not a
// rooted Windows path. A drive-letter path, an extended-length or device path
// (\\?\, \\.\), and the admin share of this machine (\\localhost\c$,
// \\127.0.0.1\c$) read as the drive path; any other share keeps its server
// and share. In every name the part after a colon (an alternate data stream,
// such as ::$DATA) is dropped, trailing dots and spaces are dropped as Win32
// does, dot segments are resolved, and an 8.3 short name is expanded.
func windowsOpenedPath(spelling string) (string, bool) {
	if !windowsRootedSpelling(spelling) {
		return "", false
	}
	root, rest, ok := windowsPathRoot(strings.ReplaceAll(spelling, `\`, "/"))
	if !ok {
		return "", false
	}
	var names []string
	for _, name := range strings.Split(rest, "/") {
		if colon := strings.IndexByte(name, ':'); colon >= 0 {
			name = name[:colon]
		}
		switch trimmed := strings.TrimRight(name, ". "); {
		case name == "..":
			if len(names) > 0 {
				names = names[:len(names)-1]
			}
		case trimmed != "":
			names = append(names, trimmed)
		}
	}
	opened := root + "/" + strings.Join(names, "/")
	if strings.Contains(opened, "~") && actionfacts.DriveLetterPath(opened) {
		opened = expandWindowsShortNames(opened)
	}
	return opened, true
}

// windowsRootedSpelling is the cheap test before windowsOpenedPath reads a
// spelling: it starts with a drive letter or with two separators.
func windowsRootedSpelling(spelling string) bool {
	if len(spelling) >= 2 && (spelling[0] == '\\' || spelling[0] == '/') &&
		(spelling[1] == '\\' || spelling[1] == '/') {
		return true
	}
	return actionfacts.DriveLetterPath(spelling)
}

// windowsPathRoot splits a slash-spelled rooted Windows path into its root
// (a drive such as C:, or //server/share) and the rest.
func windowsPathRoot(slashed string) (root, rest string, ok bool) {
	text := slashed
	for _, prefix := range []string{"//?/", "//./"} {
		if after, found := strings.CutPrefix(text, prefix); found {
			text = after
			break
		}
	}
	if len(text) >= 4 && strings.EqualFold(text[:4], "unc/") {
		text = "//" + text[4:]
	}
	if actionfacts.DriveLetterPath(text) {
		return strings.ToUpper(text[:2]), text[3:], true
	}
	if !strings.HasPrefix(text, "//") {
		return "", "", false
	}
	parts := strings.SplitN(strings.TrimLeft(text, "/"), "/", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	if len(parts) == 3 {
		rest = parts[2]
	}
	host, share := parts[0], parts[1]
	if len(share) == 2 && share[1] == '$' && windowsLocalHost(host) {
		if letter := share[0] | 0x20; 'a' <= letter && letter <= 'z' {
			return strings.ToUpper(share[:1]) + ":", rest, true
		}
	}
	return "//" + host + "/" + share, rest, true
}

// windowsLocalHost reports a server name that is this machine: localhost,
// a loopback address, or the machine name.
func windowsLocalHost(host string) bool {
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return true
	}
	// An IPv6 literal is spelled with dashes and a reserved domain in a
	// share name (::1 is 0--1.ipv6-literal.net).
	if literal, ok := strings.CutSuffix(strings.ToLower(host), ".ipv6-literal.net"); ok {
		host = strings.ReplaceAll(literal, "-", ":")
	}
	if address := net.ParseIP(host); address != nil {
		return address.IsLoopback()
	}
	name, err := windowsLocalHostname()
	return err == nil && name != "" && strings.EqualFold(host, name)
}

// pathFactSpelling is the spelling a path fact is read by: the resolved path,
// else the normalized one, else the operand as written.
func pathFactSpelling(path actionfacts.PathFact) string {
	switch {
	case path.Resolved != "":
		return path.Resolved
	case path.Normalized != "":
		return path.Normalized
	}
	return path.Value
}

// pathFactSpellings are the spellings the path rules read a path fact in:
// the operand as written, its normalized and resolved forms, and, for a
// Windows path, the path Windows opens for it (windowsOpenedPath).
func pathFactSpellings(path actionfacts.PathFact) []string {
	spellings := []string{path.Value, path.Normalized, path.Resolved}
	if opened, ok := windowsOpenedPath(pathFactSpelling(path)); ok {
		spellings = append(spellings, opened)
	}
	return spellings
}

// windowsRuleText is the text the path rules read for a path Windows opens
// (windowsOpenedPath). The home of the user is spelled ~. Elsewhere, a
// folder named Users or home followed by an account folder is a home, as on
// the other platforms: the folder names are spelled as the rules write them,
// the account folder is made a word the rules can read, and the names below
// are read in the lower case the rules write them in (windowsNameFold). A
// path with no such folder is read as it is.
func windowsRuleText(opened, home string) string {
	text := activeHomeAsTilde(opened, home)
	if rest, ok := strings.CutPrefix(text, "~/"); ok {
		return "~/" + windowsNameFold(rest)
	}
	parts := strings.Split(text, "/")
	first := -1
	for index := 0; index+1 < len(parts) && first < 0; index++ {
		if name := windowsNameFold(parts[index]); name == "users" || name == "home" {
			first = index
		}
	}
	if first < 0 {
		return text
	}
	for index := first; index < len(parts); index++ {
		name := windowsNameFold(parts[index])
		parts[index] = name
		if (name == "users" || name == "home") && index+1 < len(parts) {
			if name == "users" {
				parts[index] = "Users"
			}
			index++
			parts[index] = windowsAccountFolder(parts[index])
		}
	}
	return strings.Join(parts, "/")
}

// windowsAccountFolder is an account folder name as the rules can read it: as
// it is when it is a word, else a word.
func windowsAccountFolder(name string) string {
	if windowsAccountWord.MatchString(name) {
		return name
	}
	return "account"
}
