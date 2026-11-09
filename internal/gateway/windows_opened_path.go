// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net"
	"os"
	"regexp"
	"strings"
	"unicode"

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

// expandWindowsShortNames is the long-name form the file system gives a
// drive-letter path in forward-slash spelling: each 8.3 short name replaced
// by the name it stands for. A short name need not contain a tilde, so every
// such path is asked. A part that does not exist is left as written. The
// verbatim flag says the spelling had the extended-length prefix \\?\, which
// the file system must be asked with, not without it: Win32 does not
// normalize that path, so a name with trailing dots or spaces is the file of
// its own. An error says the file system could not answer (a folder it
// cannot list): the path is returned as written, and the caller decides by
// profile what that means (windowsAliasUnverifiedFinding). The Windows build
// asks the file system; other builds and tests replace it.
var expandWindowsShortNames = osExpandWindowsShortNames

// windowsProfileFolder reports a folder that holds the entries only the
// folder of a user profile holds (NTUSER.DAT, AppData). The Windows build
// asks the file system; other builds and tests replace it.
var windowsProfileFolder = osWindowsProfileFolder

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
// such as ::$DATA) is dropped, dot segments are resolved, and an 8.3 short
// name is expanded. Trailing dots and spaces are dropped as Win32 does, except
// in a path with the exact extended-length prefix \\?\: Win32 does not
// normalize that one, so a name with trailing dots or spaces there is a file
// of its own. The forward-slash spelling of that prefix, and every other
// device prefix, is normalized like an ordinary path.
//
// The analysis of a call keeps a path in forward-slash spelling only, so the
// caller says with verbatim whether the operand, as written, had the exact
// prefix (windowsVerbatimOperand). The error is the one of the file system
// when it could not expand the short names of the path; the path is then as
// written, and the caller decides by profile (strict closes on it).
func windowsOpenedPath(spelling string, verbatim bool) (string, bool, error) {
	if !windowsRootedSpelling(spelling) {
		return "", false, nil
	}
	slashed := strings.ReplaceAll(spelling, `\`, "/")
	root, rest, ok := windowsPathRoot(slashed)
	if !ok {
		return "", false, nil
	}
	var names []string
	for _, name := range strings.Split(rest, "/") {
		if colon := strings.Index(name, ":"); colon >= 0 {
			name = name[:colon]
		}
		trimmed := name
		if !verbatim {
			trimmed = strings.TrimRight(name, ". ")
		}
		switch {
		case name == "..":
			if len(names) > 0 {
				names = names[:len(names)-1]
			}
		case name != "." && trimmed != "":
			names = append(names, trimmed)
		}
	}
	opened := root + "/" + strings.Join(names, "/")
	var err error
	if actionfacts.DriveLetterPath(opened) {
		opened, err = expandWindowsShortNames(opened, verbatim)
	}
	return opened, true, err
}

// windowsVerbatimOperand reports an operand that, as the caller wrote it, has
// the exact extended-length prefix: only that backslash spelling skips the
// normalization of Win32.
func windowsVerbatimOperand(operand string) bool {
	return strings.HasPrefix(operand, `\\?\`)
}

// windowsOpenedPathOfFact is windowsOpenedPath for a path fact: its spelling
// is the resolved, else the normalized path, and its prefix is the one of the
// operand as written (Value). A leading space is no part of a path.
func windowsOpenedPathOfFact(path actionfacts.PathFact) (string, bool, error) {
	trim := func(text string) string { return strings.TrimLeftFunc(text, unicode.IsSpace) }
	return windowsOpenedPath(trim(pathFactSpelling(path)), windowsVerbatimOperand(trim(path.Value)))
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
	if opened, ok, _ := windowsOpenedPathOfFact(path); ok {
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
// drive-letter path with no such folder, below a folder that holds the
// entries of a user profile, is read as the home of that account too. Any
// other path is read as it is.
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
		return windowsProfileRuleText(text)
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

// windowsProfileRuleText reads a drive-letter path whose folder is the profile
// of an account that is not in a Users or home folder (a profile moved to
// another folder or drive) as the home of that account: the outermost folder
// that holds the entries of a profile (a drive root included) is the home, and
// its name the account.
// The names below are read in the lower case the rules write them in. A path
// with no such folder, or one the file system cannot be asked about, is read
// as it is.
func windowsProfileRuleText(text string) string {
	if !actionfacts.DriveLetterPath(text) {
		return text
	}
	parts := strings.Split(text, "/")
	for end := 1; end < len(parts); end++ {
		if windowsProfileFolder(strings.Join(parts[:end], "/")) {
			return parts[0] + "/Users/" + windowsAccountFolder(parts[end-1]) + "/" +
				windowsNameFold(strings.Join(parts[end:], "/"))
		}
	}
	return text
}

// markTrailingSpaces spells each space that ends a name of an opened path as
// a visible character (U+2423), so that a matcher which trims whitespace does
// not read a file named with trailing spaces (extended-length path only) as
// the file of the name without them.
func markTrailingSpaces(opened string) string {
	names := strings.Split(opened, "/")
	for index, name := range names {
		if trimmed := strings.TrimRight(name, " "); trimmed != name {
			names[index] = trimmed + strings.Repeat("\u2423", len(name)-len(trimmed))
		}
	}
	return strings.Join(names, "/")
}

// holdsProfileEntries reports a folder that holds the entries of a user
// profile: NTUSER.DAT, a file, or AppData, a folder. An entry of that name of
// the other kind (a project file called AppData) is no marker. stat answers
// for a path in forward-slash spelling.
func holdsProfileEntries(dir string, stat func(string) (os.FileInfo, error)) bool {
	for _, marker := range []struct {
		name   string
		folder bool
	}{{"NTUSER.DAT", false}, {"AppData", true}} {
		if info, err := stat(dir + "/" + marker.name); err == nil && info.IsDir() == marker.folder {
			return true
		}
	}
	return false
}

// profileHomeAtOrAbove reports a drive-letter path that lies in a folder of a
// user profile found by its entries (windowsProfileRuleText) whose folder is
// the folder cwd or lies below it: a call that runs in a profile, or in the
// folder that holds profiles, names the credential files of an account, not
// the fixtures of a project. A call that runs deeper in the profile is a
// project of the account. Both arguments are in forward-slash spelling.
func profileHomeAtOrAbove(resolved, cwd string) bool {
	if !actionfacts.DriveLetterPath(resolved) {
		return false
	}
	parts := strings.Split(resolved, "/")
	for end := 1; end < len(parts); end++ {
		if home := strings.Join(parts[:end], "/"); windowsProfileFolder(home) {
			return pathWithin(home, cwd)
		}
	}
	return false
}

// windowsAliasUnverifiedRuleID is the finding of a call that changes a
// Windows path whose 8.3 short names the file system could not expand.
const (
	windowsAliasUnverifiedRuleID = "TOOL-PATH-UNVERIFIED"
	windowsAliasUnverifiedTitle  = "Windows file path whose short names could not be resolved; the file it opens cannot be verified"
)

// appendWindowsAliasUnverifiedFinding adds the finding of a call that writes,
// appends to or deletes a Windows path the file system could not be asked
// about (a folder of the path it cannot list): a short name in that path may
// be the alias of a protected file. The finding is HIGH, so the default and
// permissive profiles show it as an alert and let the call run, and the strict
// profile, which blocks from MEDIUM, closes. Like every finding it only
// blocks where the call is enforcement-capable.
func appendWindowsAliasUnverifiedFinding(
	findings []RuleFinding,
	request trustedActionRequest,
	facts actionfacts.Facts,
) []RuleFinding {
	for _, finding := range findings {
		if finding.RuleID == windowsAliasUnverifiedRuleID {
			return findings
		}
	}
	for _, path := range facts.Paths {
		switch path.Access {
		case actionfacts.PathAccessWrite, actionfacts.PathAccessAppend, actionfacts.PathAccessDelete:
		default:
			continue
		}
		if _, ok, err := windowsOpenedPathOfFact(path); !ok || err == nil {
			continue
		}
		enforcement := findingEnforcementAllowed
		if !request.EnforcementCapable {
			enforcement = findingEnforcementDetectionOnly
		}
		return append(findings, RuleFinding{
			RuleID:      windowsAliasUnverifiedRuleID,
			Title:       windowsAliasUnverifiedTitle,
			Severity:    "HIGH",
			Confidence:  1,
			Tags:        []string{"tool-arguments"},
			LineNumber:  1,
			enforcement: enforcement,
		})
	}
	return findings
}
