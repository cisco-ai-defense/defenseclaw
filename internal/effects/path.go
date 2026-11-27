// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/asciifold"
)

// This file resolves and cleans paths under an explicit Flavor, with no use of
// path/filepath (which follows the build OS) and no filesystem access. Windows
// rules therefore run identically on Linux, as table tests.

// placePath turns a path operand spelling into a lexically resolved absolute
// path and reports whether it is statically known. It never follows links.
// ok=false carries the reason the target cannot be placed.
func placePath(spelling string, o Options) (abs string, ok bool, reason ReasonCode) {
	if o.flavor() == FlavorWindows {
		spelling = localWindowsURIPath(spelling)
	}
	if spelling == "" {
		return "", false, ReasonDynamicExpansion
	}
	if o.flavor() != FlavorWindows && o.Dialect == DialectPowerShell {
		return placePowerShellPOSIX(spelling, o)
	}
	// A path is KNOWN only in canonical form for its dialect; any other spelling
	// is unknown so it never produces a different KNOWN key (review R3-7).
	if r := canonicalIssue(spelling, o.flavor()); r != "" {
		return "", false, r
	}
	if o.flavor() == FlavorWindows {
		return placeWindows(spelling, o)
	}
	return placePOSIX(spelling, o)
}

// placePowerShellPOSIX places a path a PowerShell script names on Linux or
// macOS (GAP-1142, GAP-1255). PowerShell, not the kernel, turns the spelling
// into the path it opens: its FileSystem provider takes \ as a separator on
// every platform and a leading ~ as the home, and it resolves . and .. by
// name against the location, as .NET's Path.GetFullPath does under every
// file API. So a .. is a lexical step here, not the physical one a POSIX
// shell's open takes after a link, and ../x, ~\x and a\..\x are placed like
// their written-out paths. A provider-qualified spelling (FileSystem::), a
// PowerShell drive (Env:, HKCU:, Temp:) or a UNC is not a placed file path.
func placePowerShellPOSIX(spelling string, o Options) (string, bool, ReasonCode) {
	s := strings.ReplaceAll(spelling, `\`, "/")
	if strings.HasPrefix(s, "//") || strings.Contains(s, "::") {
		return "", false, ReasonNonCanonicalPath
	}
	if i := strings.IndexByte(s, ':'); i > 0 && !strings.Contains(s[:i], "/") {
		return "", false, ReasonNonCanonicalPath
	}
	return placePOSIX(s, o)
}

// canonicalIssue reports a non-canonical path spelling that must not be placed
// to a KNOWN key (review R3-7): 8.3 short names, \\.\ device and admin-share
// UNC, PowerShell provider prefixes and non-FileSystem drives, cmd %~/%N/%%
// tokens, and MSYS roots other than a drive mount.
func canonicalIssue(s string, flavor Flavor) ReasonCode {
	if flavor == FlavorWindows {
		w := strings.ReplaceAll(s, "/", `\`)
		switch {
		case strings.HasPrefix(w, `\\.\`), strings.HasPrefix(w, `\\?\`):
			return ReasonNonCanonicalPath
		case strings.HasPrefix(w, `\\`): // UNC / admin share (incl. localhost, 127.0.0.1)
			return ReasonNonCanonicalPath
		case strings.Contains(s, "::"): // provider-qualified path (FileSystem::, Env:\)
			return ReasonNonCanonicalPath
		case strings.Contains(w, "%"): // %VAR% left unexpanded, %~dp0, %1, %%P%%
			return ReasonNonCanonicalPath
		case hasShortNameSegment(w):
			return ReasonNonCanonicalPath
		case hasTrailingDotOrSpaceSegment(w):
			return ReasonNonCanonicalPath // "x.exe ." / "x." name the base file (review R5-5)
		case hasADSStream(w):
			return ReasonNonCanonicalPath // an alternate data stream name
		}
		// a non-FileSystem PowerShell drive (Env:, HKLM:, Variable:, Cert:)
		if i := strings.IndexByte(s, ':'); i > 1 {
			drive := strings.ToLower(s[:i])
			switch drive {
			case "env", "hklm", "hkcu", "variable", "cert", "function", "alias", "wsman":
				return ReasonNonCanonicalPath
			}
		}
		return ""
	}
	// POSIX: a path with a .. (after a component that might be a symlink), a
	// //, a /./ or a trailing /. is not canonical and must not be lexically
	// collapsed to a KNOWN key until the resolver can follow links (review
	// N4-4). ANSI-C quoting is caught at the word level.
	if strings.Contains(s, "//") || strings.Contains(s, "/./") {
		return ReasonNonCanonicalPath
	}
	if s == ".." || strings.HasPrefix(s, "../") || strings.HasSuffix(s, "/..") || strings.Contains(s, "/../") {
		return ReasonNonCanonicalPath
	}
	if strings.HasSuffix(s, "/.") {
		return ReasonNonCanonicalPath
	}
	return ""
}

func hasShortNameSegment(w string) bool {
	for _, seg := range strings.Split(w, `\`) {
		if i := strings.IndexByte(seg, '~'); i > 0 && i+1 < len(seg) && seg[i+1] >= '0' && seg[i+1] <= '9' {
			return true
		}
	}
	return false
}

func placePOSIX(spelling string, o Options) (string, bool, ReasonCode) {
	s := spelling
	switch {
	case s == "~" || strings.HasPrefix(s, "~/"):
		if o.Home == "" {
			return "", false, ReasonDynamicExpansion
		}
		s = o.Home + strings.TrimPrefix(s, "~")
	case strings.HasPrefix(s, "~"):
		// ~name: the named account's home when the caller vouched for it, a
		// literal folder when name can never be a login, else unknown.
		h, ok, reason := tildeAccount(s, o)
		if !ok {
			return "", false, reason
		}
		s = h
	}
	if !strings.HasPrefix(s, "/") {
		if o.CWD == "" || !strings.HasPrefix(o.CWD, "/") {
			return "", false, ReasonDynamicCWD
		}
		s = o.CWD + "/" + s
	}
	return cleanPOSIX(s), true, ""
}

// tildeAccount expands a POSIX ~name prefix (s starts with ~ and is not ~ or
// ~/). The active login and the accounts the caller vouched for expand to their
// home; a name that can never be a login (., .., or a character no login has)
// is the literal folder ~name, as bash keeps a tilde word whose lookup fails
// (rel-1-0-10:GAP-0948); ~+ and ~- and the directory-stack forms are the
// walker's (resolveWord), so here they are unknown.
func tildeAccount(s string, o Options) (string, bool, ReasonCode) {
	name, rest := s[1:], ""
	if i := strings.IndexByte(name, '/'); i >= 0 {
		name, rest = name[:i], name[i:]
	}
	switch {
	case name == "" || name[0] == '+' || name[0] == '-':
		return "", false, ReasonDynamicExpansion
	case !validLoginName(name):
		return "./" + s, true, ""
	case o.Login != "" && strings.EqualFold(name, o.Login):
		home := o.loginHome
		if home == "" {
			home = o.Home
		}
		if home == "" {
			return "", false, ReasonDynamicExpansion
		}
		return strings.TrimRight(home, "/") + rest, true, ""
	}
	if h, ok := o.Accounts[name]; ok && strings.HasPrefix(h, "/") {
		return strings.TrimRight(h, "/") + rest, true, ""
	}
	return "", false, ReasonDynamicExpansion
}

// TildeAccountNames lists, once each and in order, the login names text spells
// as a POSIX ~name prefix: a ~ at the start of the text or after a blank, an
// operator, a quote, = or : (an over-reading: the caller looks each name up for
// Options.Accounts, and a name the walk never expands costs only that lookup).
// ~, ~/, ~+, ~- and names no login can have are not listed.
func TildeAccountNames(text string) []string {
	const before, after = " \t\n\r;&|()<>=:`\"'{},", "/ \t\n\r;&|()<>`\"'{},:"
	var names []string
	for i := strings.IndexByte(text, '~'); i >= 0; {
		if i == 0 || strings.IndexByte(before, text[i-1]) >= 0 {
			name := text[i+1:]
			if j := strings.IndexAny(name, after); j >= 0 {
				name = name[:j]
			}
			if validLoginName(name) && !slices.Contains(names, name) {
				names = append(names, name)
			}
		}
		j := strings.IndexByte(text[i+1:], '~')
		if j < 0 {
			break
		}
		i += 1 + j
	}
	return names
}

// validLoginName reports a name the passwd lookup of a tilde prefix can find:
// the POSIX portable login characters (plus @ and the trailing $ of a machine
// account), never . or .. and never a leading -.
func validLoginName(name string) bool {
	if name == "" || name == "." || name == ".." || name[0] == '-' {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '.', c == '_', c == '-', c == '@':
		case c == '$' && i == len(name)-1:
		default:
			return false
		}
	}
	return true
}

// lexicalCandidate is the Target.Lexical of a spelling placePath refused as
// not canonical: the absolute path it names with home, account and working
// folder applied and nothing collapsed, so the resolver can walk it physically
// (a .. after a link climbs from the link's target) and the classifier can read
// it as a pattern. Empty when the spelling has no such candidate (a device or
// share prefix, a provider path, an unexpanded %VAR%, an unknown folder).
func lexicalCandidate(spelling string, o Options) string {
	if spelling == "" {
		return ""
	}
	if o.flavor() == FlavorWindows {
		w := strings.ReplaceAll(spelling, "/", `\`)
		if strings.HasPrefix(w, `\\`) || strings.Contains(spelling, "::") || strings.Contains(w, "%") {
			return ""
		}
		// Win32 collapses . and .. by name before the file system sees the
		// path, so the only non-canonical part left is the 8.3-looking name,
		// a trailing dot or space or a stream: place the rest as usual.
		if abs, ok, _ := placeWindows(spelling, o); ok {
			return abs
		}
		return ""
	}
	s := spelling
	switch {
	case s == "~" || strings.HasPrefix(s, "~/"):
		if o.Home == "" {
			return ""
		}
		s = o.Home + strings.TrimPrefix(s, "~")
	case strings.HasPrefix(s, "~"):
		h, ok, _ := tildeAccount(s, o)
		if !ok {
			return ""
		}
		s = h
	}
	if !strings.HasPrefix(s, "/") {
		if o.CWD == "" || !strings.HasPrefix(o.CWD, "/") {
			return ""
		}
		s = strings.TrimRight(o.CWD, "/") + "/" + strings.TrimPrefix(s, "./")
	}
	return s
}

// cleanPOSIX collapses . and .. and repeated slashes. Pure lexical cleaning;
// it does not follow links, so a trailing .. after a symlink is lexical only.
func cleanPOSIX(p string) string {
	abs := strings.HasPrefix(p, "/")
	parts := strings.Split(p, "/")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		switch part {
		case "", ".":
			continue
		case "..":
			if len(out) > 0 && out[len(out)-1] != ".." {
				out = out[:len(out)-1]
			} else if !abs {
				out = append(out, "..")
			}
		default:
			out = append(out, part)
		}
	}
	res := strings.Join(out, "/")
	if abs {
		return "/" + res
	}
	if res == "" {
		return "."
	}
	return res
}

func placeWindows(spelling string, o Options) (string, bool, ReasonCode) {
	spelling = localWindowsURIPath(spelling)
	// A leading / on Windows depends on the dialect of the frontend walking the
	// text (review 6 #1): Git Bash / Cygwin (POSIX) use POSIX-absolute spellings
	// where only a /<drive>/ MSYS mount and /cygdrive/<drive>/ are known and
	// every other absolute path is a virtual root; cmd and PowerShell treat a
	// leading / as drive-root-relative (handled below); and when the dialect is
	// unknown or only guessed, a POSIX-absolute path has no known Windows target.
	if strings.HasPrefix(spelling, "/") {
		switch o.Dialect {
		case DialectCMD, DialectPowerShell:
			// drive-root-relative; handled by the \x branch below.
		case DialectPOSIX:
			if len(spelling) >= 2 && isDriveLetter(spelling[1]) && (len(spelling) == 2 || spelling[2] == '/') {
				rest := spelling[2:]
				if rest == "" {
					rest = "/" // bare /c is the drive root C:\, not drive-relative C: (review 6 #2)
				}
				spelling = string(spelling[1]) + ":" + rest
			} else if m, ok := cygdriveMount(spelling); ok {
				spelling = m
			} else {
				return "", false, ReasonVirtualRoot
			}
		default:
			// Windows flavor, dialect unknown or guessed: no known POSIX root.
			return "", false, ReasonVirtualRoot
		}
	}
	s := strings.ReplaceAll(spelling, "/", `\`)
	// A leading ~ is the home in PowerShell (its FileSystem provider) and a
	// literal folder name in cmd (GAP-1191): under PowerShell ~ and ~\x are
	// placed in the home; in a dialect only guessed the spelling has no known
	// target.
	if s == "~" || strings.HasPrefix(s, `~\`) {
		switch o.Dialect {
		case DialectPowerShell:
			if !windowsShapedHome(o.Home) {
				return "", false, ReasonDynamicExpansion
			}
			s = strings.TrimRight(strings.ReplaceAll(o.Home, "/", `\`), `\`) + s[1:]
		case DialectCMD:
		default:
			return "", false, ReasonDynamicExpansion
		}
	}
	// UNC and device/extended-length prefixes are kept verbatim after cleaning
	// their separators; they are absolute by construction.
	if strings.HasPrefix(s, `\\`) {
		return normalizeWindows(s, o), true, ""
	}
	// Drive-absolute: C:\x
	if len(s) >= 2 && isDriveLetter(s[0]) && s[1] == ':' {
		rest := s[2:]
		if strings.HasPrefix(rest, `\`) {
			return normalizeWindows(s, o), true, ""
		}
		// C:foo is relative to the current folder of drive C. That is the
		// working folder when the working folder is on C (Win32 keeps one
		// current folder per drive, and the process's is its own drive's);
		// another drive's current folder is unknown (review P2,
		// rel-1-0-10:GAP-1078).
		if cwd := strings.ReplaceAll(o.CWD, "/", `\`); len(cwd) >= 3 && isDriveLetter(cwd[0]) && cwd[1] == ':' && cwd[2] == '\\' &&
			strings.EqualFold(cwd[:1], s[:1]) && !strings.HasPrefix(o.CWD, `\\`) {
			return normalizeWindows(strings.TrimRight(cwd, `\`)+`\`+rest, o), true, ""
		}
		return "", false, ReasonDynamicCWD
	}
	// Root-relative \x (relative to current drive).
	if strings.HasPrefix(s, `\`) {
		if o.Drive == "" {
			if o.CWD != "" && len(o.CWD) >= 2 && isDriveLetter(o.CWD[0]) {
				return normalizeWindows(string(o.CWD[0])+":"+s, o), true, ""
			}
			return "", false, ReasonDynamicCWD
		}
		return normalizeWindows(o.Drive+":"+s, o), true, ""
	}
	// Plain relative.
	if o.CWD == "" {
		return "", false, ReasonDynamicCWD
	}
	return normalizeWindows(strings.TrimRight(o.CWD, `\`)+`\`+s, o), true, ""
}

// windowsShapedHome reports a drive-absolute home (C:\Users\alice) a
// PowerShell ~ can stand for.
func windowsShapedHome(home string) bool {
	return len(home) >= 3 && isDriveLetter(home[0]) && home[1] == ':' && (home[2] == '\\' || home[2] == '/')
}

// normalizeWindows cleans . and .. segments, trims trailing dots and spaces on
// the final element (a Windows filesystem quirk that lets "x.exe ." name
// "x.exe"), and folds case when CaseInsensitive. A flagged special form must
// either normalize here or be rejected upstream -- never "known but flagged".
// localWindowsURIPath recognizes the local file URI spelling emitted by some
// Windows tools. localhost:///C:/x is a drive path, not a UNC share whose
// server is "C:".
func localWindowsURIPath(spelling string) string {
	const prefix = "localhost:///"
	if len(spelling) < len(prefix) || !strings.EqualFold(spelling[:len(prefix)], prefix) {
		return spelling
	}
	rest := spelling[len(prefix):]
	if len(rest) < 3 || !isDriveLetter(rest[0]) || rest[1] != ':' || (rest[2] != '/' && rest[2] != '\\') {
		return spelling
	}
	return rest
}

func normalizeWindows(p string, o Options) string {
	prefix := ""
	body := p
	for _, pre := range []string{`\\?\`, `\\.\`} {
		if strings.HasPrefix(body, pre) {
			prefix = pre
			body = body[len(pre):]
			break
		}
	}
	unc := ""
	if prefix == "" && strings.HasPrefix(body, `\\`) {
		unc = `\\`
		body = body[2:]
	}
	var drive string
	if len(body) >= 2 && isDriveLetter(body[0]) && body[1] == ':' {
		drive = body[:2]
		body = body[2:]
	}
	parts := strings.Split(body, `\`)
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		switch part {
		case "", ".":
			continue
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, part)
		}
	}
	for i := range out {
		// the default-stream alias ::$DATA names the file itself (review WP2),
		// and the index alias of a folder the folder (rel-1-0-10:GAP-1075).
		if idx := strings.Index(asciifold.Lower(out[i]), "::$data"); idx >= 0 {
			out[i] = out[i][:idx]
		} else {
			out[i] = withoutFolderIndexAlias(out[i])
		}
		out[i] = strings.TrimRight(out[i], " .")
		if out[i] == "" {
			out[i] = "_"
		}
	}
	res := prefix + unc + drive
	if len(out) > 0 {
		joined := strings.Join(out, `\`)
		if res == "" || strings.HasSuffix(res, `\`) {
			res += joined
		} else {
			res += `\` + joined
		}
	} else if res == "" {
		res = `\`
	}
	if o.CaseInsensitive {
		res = strings.ToLower(res)
	}
	return res
}

// withoutFolderIndexAlias is a folder name without its index alias
// (dir::$INDEX_ALLOCATION, dir:$I30:$INDEX_ALLOCATION, any case): NTFS opens
// the folder itself for it, so a file below it is the file below the folder.
func withoutFolderIndexAlias(name string) string {
	trimmed := strings.TrimRight(name, ".")
	for _, alias := range [...]string{"::$INDEX_ALLOCATION", ":$I30:$INDEX_ALLOCATION"} {
		if n := len(trimmed) - len(alias); n > 0 && strings.EqualFold(trimmed[n:], alias) {
			return trimmed[:n]
		}
	}
	return name
}

func isDriveLetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// Key returns the canonical join key for a target: the physical path when the
// resolver has run, else the lexical path, case-folded for a case-insensitive
// flavor. It is the one key used for in-call link/data joins and chain join
// digests (review R7).
func (t Target) Key() string {
	v := t.Path
	if t.Physical != "" {
		v = t.Physical
	}
	if v == "" {
		return ""
	}
	if t.Flavor == FlavorWindows {
		return strings.ToLower(strings.ReplaceAll(v, "/", `\`))
	}
	// A case-insensitive POSIX filesystem (macOS default) folds the key so two
	// spellings of one protected file match (review R5-5).
	if t.CaseFold {
		return strings.ToLower(v)
	}
	return v
}

// looksGlob reports whether an unquoted word is a shell glob or brace-list
// pattern. A brace list ({a,b}) expands to several paths, so it is treated as a
// pattern (unknown) rather than one literal file (review PX-6, Q2).
func looksGlob(s string) bool {
	if strings.ContainsAny(s, "*?[") {
		return true
	}
	if i := strings.IndexByte(s, '{'); i >= 0 {
		if j := strings.IndexByte(s[i:], '}'); j > 0 && strings.Contains(s[i:i+j], ",") {
			return true
		}
	}
	return false
}

// KnownPathCanonical reports whether a path spelling is canonical for its
// flavor (the harness self-audit uses it to confirm no KNOWN path is
// non-canonical over the corpus -- review N4-6).
func KnownPathCanonical(spelling string, flavor Flavor) bool {
	return canonicalIssue(spelling, flavor) == ""
}

// hasTrailingDotOrSpaceSegment reports a Windows path segment ending in '.' or
// ' ', which Windows silently maps to the base name -- not canonical (R5-5).
func hasTrailingDotOrSpaceSegment(w string) bool {
	for _, seg := range strings.Split(w, `\`) {
		if len(seg) >= 2 && seg[1] == ':' && len(seg) == 2 {
			continue // drive letter
		}
		if seg != "" && (strings.HasSuffix(seg, ".") || strings.HasSuffix(seg, " ")) &&
			seg != "." && seg != ".." {
			return true
		}
	}
	return false
}

// hasADSStream reports a Windows alternate-data-stream suffix (file:stream) in a
// non-drive segment -- not canonical (R5-5).
func hasADSStream(w string) bool {
	for _, seg := range strings.Split(w, `\`) {
		c := strings.IndexByte(seg, ':')
		if c < 0 {
			continue
		}
		if c == 1 && len(seg) >= 2 && isDriveLetter(seg[0]) {
			// drive-letter colon is fine only when it's the leading segment's
			// drive; a second colon in the same segment is a stream.
			if strings.IndexByte(seg[2:], ':') >= 0 {
				return true
			}
			continue
		}
		return true
	}
	return false
}

// cygdriveMount maps a Cygwin /cygdrive/<drive>/rest to <drive>:\rest. ok is
// false for anything else (incl. /proc/cygdrive/... which is not this form).
func cygdriveMount(s string) (string, bool) {
	const p = "/cygdrive/"
	if !strings.HasPrefix(s, p) || len(s) < len(p)+1 {
		return "", false
	}
	d := s[len(p)]
	rest := s[len(p)+1:]
	if !isDriveLetter(d) || (rest != "" && rest[0] != '/') {
		return "", false
	}
	if rest == "" {
		rest = "/" // /cygdrive/c is the drive root C:\, not drive-relative C: (review 6 #2)
	}
	return string(d) + ":" + rest, true
}
