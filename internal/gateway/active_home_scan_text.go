// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// ruleReadableHome is the user home the home-relative path rules read in a
// path: /root, /home/<word> and /Users/<word>. A home of another shape (a
// dotted or hyphenated account name, a directory-service name, a home under
// another root) is invisible to those rules, so the same credential file
// that is judged by its name elsewhere would be judged by no rule in it. A
// Windows drive home is never listed here: the rules read the folder names
// in one letter case and Windows reads them in any.
var ruleReadableHome = regexp.MustCompile(`^(?:/root|/home/\w+|/Users/\w+)$`)

// activeHomeAsTilde spells the active home in text as ~, which every
// home-relative path rule reads, when the rules cannot read the home as it
// is. The file the caller owns is then judged by the same rule as the same
// name under a home of the usual shape. Only the home as a whole path prefix
// is respelled: not a longer name, not a path that merely ends in it. A
// drive-letter home is read in the forward-slash spelling the path facts
// give, and compared as Windows compares names: without regard to letter
// case, in any script, and through upper case, so an account name such as an
// accented one matches its other case and a dotless i matches i.
func activeHomeAsTilde(text, home string) string {
	return respellActiveHome(text, home, false)
}

// respellActiveHome is activeHomeAsTilde with the Windows name comparison
// also available for a POSIX home (foldPOSIX), for a host whose file system
// names a file in any letter case (see pathCaseFoldHost).
func respellActiveHome(text, home string, foldPOSIX bool) string {
	home = strings.TrimRight(strings.ReplaceAll(home, `\`, "/"), "/")
	windows := actionfacts.DriveLetterPath(home + "/")
	if len(home) < 2 || !windows && (home[0] != '/' || ruleReadableHome.MatchString(home)) {
		return text
	}
	needle := home + "/"
	find := func(from int) (int, int) {
		offset := strings.Index(text[from:], needle)
		if offset < 0 {
			return -1, -1
		}
		return from + offset, from + offset + len(needle)
	}
	if windows || foldPOSIX {
		find = func(from int) (int, int) { return indexFoldedPrefix(text, needle, from) }
	}
	var out strings.Builder
	last := 0
	for from := 0; ; {
		start, end := find(from)
		if start < 0 {
			break
		}
		// The match ends after the slash that closes the home; the home
		// itself ends one byte earlier.
		from = end - 1
		if start > 0 && (strings.IndexByte("_.-/~$}", text[start-1]) >= 0 || asciiAlphanumeric(text[start-1])) {
			continue
		}
		out.WriteString(text[last:start])
		out.WriteByte('~')
		last = from
	}
	if last == 0 {
		return text
	}
	out.WriteString(text[last:])
	return out.String()
}

// indexFoldedPrefix finds needle in text from byte offset from, comparing
// letters as a Windows file system does (see windowsLetterEqual), and returns
// the byte span of the match in text (which can differ in length from needle)
// or -1, -1. A match begins with the ASCII drive letter of needle, so most
// positions are rejected on one byte.
func indexFoldedPrefix(text, needle string, from int) (int, int) {
	first := asciiLower(needle[0])
	for start := from; start < len(text); start++ {
		if asciiLower(text[start]) != first {
			continue
		}
		if length, ok := foldedPrefixLength(text[start:], needle); ok {
			return start, start + length
		}
	}
	return -1, -1
}

// foldedPrefixLength reports whether text starts with needle letter for letter
// under windowsLetterEqual, and the byte length of that prefix of text.
func foldedPrefixLength(text, needle string) (int, bool) {
	end := 0
	for _, want := range needle {
		if end >= len(text) {
			return 0, false
		}
		got, size := utf8.DecodeRuneInString(text[end:])
		if got == utf8.RuneError && size == 1 || !windowsLetterEqual(got, want) {
			return 0, false
		}
		end += size
	}
	return end, true
}

// windowsLetterEqual reports whether two letters of a Windows name are the same
// letter. Windows compares names through upper case, so a letter that
// upper-cases to the same letter as another is that letter even when Unicode
// simple case folding does not group them (dotless i and i). Letters grouped by
// simple case folding stay equal, as they always were here.
func windowsLetterEqual(a, b rune) bool {
	if a == b || unicode.ToUpper(a) == unicode.ToUpper(b) {
		return true
	}
	for folded := unicode.SimpleFold(a); folded != a; folded = unicode.SimpleFold(folded) {
		if folded == b {
			return true
		}
	}
	return false
}

func asciiLower(b byte) byte {
	if 'A' <= b && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

func asciiAlphanumeric(b byte) bool {
	return 'a' <= b && b <= 'z' || 'A' <= b && b <= 'Z' || '0' <= b && b <= '9'
}

// relativeHomeWritesAsTilde spells, in text, each relative operand that the
// facts prove the call writes, appends to or deletes in the caller's home as
// the same file under ~ (cp /tmp/x .aws/credentials from the home reads as
// cp /tmp/x ~/.aws/credentials). The home-relative path rules read a file in
// the home only through a home spelling (~, $HOME, /home/<word>), so the same
// write with a relative operand, or after a cd into the home, was judged by
// none of them: PATH-AWS-CREDS blocked the ~/ spelling and allowed the
// relative one (substrate-1:GAP-0697). The rules that read the path facts
// already judge the resolved file, so the respelling changes only what those
// text rules read.
//
// Only an exact reading counts: the facts must be complete, and an operand
// read in another folder its command may run in (OtherFolderReading), in a
// folder the call does not give (UnresolvedFolder), or through a link is left
// as written; those keep their own tiers. A partial call is judged here by the
// pass of each of its simple commands, whose folder the walk gives. Each
// spelling of the operand in text is respelled; the call writes that file, so
// a second mention of the same word cannot add a finding the write does not
// already earn.
func relativeHomeWritesAsTilde(text string, facts actionfacts.Facts) string {
	home := strings.TrimRight(facts.ActiveHome, "/")
	if text == "" || !facts.Authoritative() || len(home) < 2 || home[0] != '/' {
		return text
	}
	for _, candidate := range facts.Paths {
		switch candidate.Access {
		case actionfacts.PathAccessWrite, actionfacts.PathAccessAppend, actionfacts.PathAccessDelete:
		default:
			continue
		}
		value := candidate.Value
		if candidate.Linked || candidate.OtherFolderReading() || candidate.UnresolvedFolder() ||
			candidate.Flavor != actionfacts.PathFlavorPOSIX || value == "" || strings.ContainsAny(value[:1], "/~$") {
			continue
		}
		below, ok := strings.CutPrefix(candidate.Resolved, home+"/")
		if !ok || below == "" || !homeRelativeLiteral(below) {
			continue
		}
		text = respellShellWord(text, value, "~/"+below)
	}
	return text
}

// homeRelativeLiteral reports whether below, a clean path under the home, is
// one shell word with no quoting: the names the path rules read.
func homeRelativeLiteral(below string) bool {
	for _, segment := range strings.Split(below, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return strings.IndexFunc(below, func(r rune) bool { return !shellLiteralRune(r, "/._-+@%,:") }) < 0
}

// shellLiteralRune reports a rune a shell reads literally in a word: an ASCII
// letter or digit, or one of punct.
func shellLiteralRune(r rune, punct string) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune(punct, r)
}

// respellShellWord replaces in text each occurrence of word that stands as a
// whole shell word or operand (after a blank, a quote, a redirect, an
// operator or an option key's "="; before a blank, a quote, a redirect or an
// operator) with spelling.
func respellShellWord(text, word, spelling string) string {
	var out strings.Builder
	last := 0
	for from := 0; from < len(text); {
		offset := strings.Index(text[from:], word)
		if offset < 0 {
			break
		}
		start, end := from+offset, from+offset+len(word)
		from = start + 1
		if start > 0 && strings.IndexByte(" \t\n'\"<>=;&|(", text[start-1]) < 0 ||
			end < len(text) && strings.IndexByte(" \t\r\n'\"<>;&|)", text[end]) < 0 {
			continue
		}
		out.WriteString(text[last:start])
		out.WriteString(spelling)
		last, from = end, end
	}
	if last == 0 {
		return text
	}
	out.WriteString(text[last:])
	return out.String()
}
