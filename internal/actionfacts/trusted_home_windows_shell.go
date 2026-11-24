// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/asciifold"
)

// trustedWindowsHomeLiteral is a Windows drive ActiveHome, as
// normalizeActiveHome spells it, that reads as the same path when written
// into a PowerShell or cmd word after quoting: no quoting, variable, escape or
// glob characters. Account names may hold any Unicode letter, mark or digit
// (C:/Users/Zoë); none of those quote or expand in PowerShell or cmd. An
// ASCII-only class left $HOME and ~ partial under such a home while the
// literal spelling was judged (GAP-1205).
var trustedWindowsHomeLiteral = lazyMustCompile(`^[A-Za-z]:/[\p{L}\p{M}\p{N}._+ /-]*$`)

// trustedUnixPowerShellHome is a Linux or macOS ActiveHome that reads as the
// same path when written into a PowerShell word: the same characters, under /.
var trustedUnixPowerShellHome = lazyMustCompile(`^/[\p{L}\p{M}\p{N}._+ /-]*$`)

// windowsShellHomeAnchors are the spellings of the caller's home a PowerShell
// or cmd word may start with, lower-cased. PowerShell's $HOME is a constant
// automatic variable; USERPROFILE and the FileSystem provider home could be
// changed by the action itself, which the caller declines.
var windowsShellHomeAnchors = map[Dialect][]string{
	DialectPowerShell: {"${home}", "$home", "${env:userprofile}", "$env:userprofile", "~"},
	DialectCMD:        {"%userprofile%"},
}

// posixPowerShellHomeAnchors are the home spellings of pwsh on Linux and
// macOS: $HOME and the FileSystem provider home ~ (USERPROFILE is not set
// there). A pwsh -Command body that writes $HOME/.codex/config.toml or
// ~/.defenseclaw/config.yaml was partial with no finding, where the same
// path written out was judged (rel-1-0-10:GAP-1134).
var posixPowerShellHomeAnchors = []string{"${home}", "$home", "~"}

// posixPowerShellScript reports a reading of a script pwsh runs, whose $HOME
// and ~ name a Linux or macOS ActiveHome: the script of a PowerShell launcher
// (Input.PowerShellLauncherBody, rel-1-0-10:GAP-1134) or the command of a
// PowerShell tool (Claude Code's PowerShell tool on Linux or macOS). Such a
// tool call that wrote $HOME/.defenseclaw/config.yaml was partial with no
// finding, where the same script in a launcher, or the path written out, was
// judged (rel-1-0-10:GAP-1214). A Windows ActiveHome never takes this case.
func posixPowerShellScript(input Input) bool {
	if input.PowerShellLauncherBody {
		return true
	}
	if input.WindowsHookHost {
		return false
	}
	switch input.DialectHint {
	case "", DialectNone, DialectPowerShell:
	default:
		return false
	}
	switch strings.ToLower(strings.TrimSpace(input.Tool)) {
	case "powershell", "powershell.exe", "pwsh", "pwsh.exe":
		return true
	}
	return false
}

// rewriteTrustedShellHome replaces each home anchor ($HOME, ~,
// $env:USERPROFILE, %USERPROFILE%) that starts a word and is followed by a
// path separator with the trusted Windows ActiveHome, and in a script pwsh
// runs under a Linux or macOS ActiveHome (posixScript, posixPowerShellScript)
// each of posixPowerShellHomeAnchors with that home. A Windows home made
// `echo k >> $HOME\.ssh\authorized_keys` and `Get-Content ~\.ssh\id_rsa`
// partial with no finding, while the same paths written out were judged
// (GAP-0912). The caller re-parses the result and keeps it only when that
// parse is complete, so any other dynamic word keeps the action partial.
//
// The rewrite declines source with an escape character, an anchor inside
// single quotes (PowerShell) or any other mention of HOME or USERPROFILE,
// which could change what the anchors name before they are expanded.
func rewriteTrustedShellHome(source, activeHome string, dialect Dialect, posixScript bool) (string, bool) {
	anchors := windowsShellHomeAnchors[dialect]
	// Written with backslashes, as cmd would otherwise read /Users as a
	// switch; PowerShell reads both separators.
	home := strings.ReplaceAll(activeHome, "/", `\`)
	switch {
	case trustedWindowsHomeLiteral.MatchString(activeHome):
	case posixScript && dialect == DialectPowerShell && trustedUnixPowerShellHome.MatchString(activeHome):
		anchors, home = posixPowerShellHomeAnchors, activeHome
	default:
		return "", false
	}
	if len(anchors) == 0 || strings.ContainsAny(source, "`^\x00") {
		return "", false
	}
	// Offsets of source are offsets of lower: asciifold.Lower keeps every
	// byte but the ASCII capitals (GAP-1934).
	lower := asciifold.Lower(source)
	var out, rest strings.Builder
	last := 0
	single, double := false, false
	for index := 0; index < len(source); index++ {
		switch character := source[index]; {
		case character == '\'' && dialect == DialectPowerShell && !double:
			single = !single
			continue
		case character == '"' && !single:
			double = !double
			continue
		case single || !windowsShellWordStart(source, index, double):
			continue
		}
		for _, anchor := range anchors {
			end := index + len(anchor)
			if !strings.HasPrefix(lower[index:], anchor) || end >= len(source) ||
				(source[end] != '\\' && source[end] != '/') ||
				(anchor == "~" && double) {
				continue
			}
			out.WriteString(source[last:index])
			rest.WriteString(source[last:index])
			if strings.Contains(home, " ") && !double {
				// Keep a space-bearing home and its literal suffix in one
				// shell word. Quoting only the home would split the path.
				suffixEnd := end
				for suffixEnd < len(source) && strings.ContainsRune(
					`\/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._+-`,
					rune(source[suffixEnd]),
				) {
					suffixEnd++
				}
				if suffixEnd < len(source) && !strings.ContainsRune(" \t;|&<>)", rune(source[suffixEnd])) {
					return "", false
				}
				out.WriteByte('"')
				out.WriteString(home)
				out.WriteString(source[end:suffixEnd])
				out.WriteByte('"')
				last = suffixEnd
				index = suffixEnd - 1
			} else {
				out.WriteString(home)
				last = end
				index = end - 1
			}
			break
		}
	}
	if last == 0 {
		return "", false
	}
	out.WriteString(source[last:])
	rest.WriteString(source[last:])
	remaining := strings.ToLower(rest.String())
	if strings.Contains(remaining, "home") || strings.Contains(remaining, "userprofile") {
		return "", false
	}
	return out.String(), true
}

// windowsShellWordStart reports whether index starts a word: the start of
// source, or after whitespace, a redirect operator, a "-Name:" parameter
// colon, or the opening quote of a double-quoted word.
func windowsShellWordStart(source string, index int, double bool) bool {
	if index == 0 {
		return true
	}
	previous := source[index-1]
	if double {
		return previous == '"' && windowsShellWordStart(source, index-1, false) ||
			previous == ' ' || previous == '\t' || previous == '>'
	}
	return previous == ' ' || previous == '\t' || previous == '>' ||
		previous == ':' && index >= 2 && source[index-2] != ' '
}
