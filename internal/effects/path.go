// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import "strings"

// This file resolves and cleans paths under an explicit Flavor, with no use of
// path/filepath (which follows the build OS) and no filesystem access. Windows
// rules therefore run identically on Linux, as table tests.

// placePath turns a path operand spelling into a lexically resolved absolute
// path and reports whether it is statically known. It never follows links.
// ok=false carries the reason the target cannot be placed.
func placePath(spelling string, o Options) (abs string, ok bool, reason ReasonCode) {
	if spelling == "" {
		return "", false, ReasonDynamicExpansion
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

// canonicalIssue reports a non-canonical path spelling that must not be placed
// to a KNOWN key (review R3-7): 8.3 short names, \\.\ device and admin-share
// UNC, PowerShell provider prefixes and non-FileSystem drives, cmd %~/%N/%%
// tokens, and MSYS roots other than a drive mount.
func canonicalIssue(s string, flavor Flavor) ReasonCode {
	if flavor == FlavorWindows {
		w := strings.ReplaceAll(s, "/", `\`)
		lw := strings.ToLower(w)
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
		_ = lw
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
		// ~user: another user's home, which we cannot place without lookup.
		return "", false, ReasonDynamicExpansion
	}
	if !strings.HasPrefix(s, "/") {
		if o.CWD == "" || !strings.HasPrefix(o.CWD, "/") {
			return "", false, ReasonDynamicCWD
		}
		s = o.CWD + "/" + s
	}
	return cleanPOSIX(s), true, ""
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
	// MSYS / Git Bash drive mount: /c/Users -> C:\Users (review N17).
	if len(spelling) >= 2 && spelling[0] == '/' && isDriveLetter(spelling[1]) &&
		(len(spelling) == 2 || spelling[2] == '/') {
		spelling = string(spelling[1]) + ":" + spelling[2:]
	}
	s := strings.ReplaceAll(spelling, "/", `\`)
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
		// C:foo is relative to the current directory on drive C, which we
		// cannot place without per-drive cwd state (review P2).
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

// normalizeWindows cleans . and .. segments, trims trailing dots and spaces on
// the final element (a Windows filesystem quirk that lets "x.exe ." name
// "x.exe"), and folds case when CaseInsensitive. A flagged special form must
// either normalize here or be rejected upstream -- never "known but flagged".
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
		// the default-stream alias ::$DATA names the file itself (review WP2).
		if idx := strings.Index(strings.ToUpper(out[i]), "::$DATA"); idx >= 0 {
			out[i] = out[i][:idx]
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
