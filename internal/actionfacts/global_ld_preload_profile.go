// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path"
	"strings"
	"unicode/utf8"
)

const globalLDPreloadProfileDirectory = "/etc/profile.d/"

const globalLDPreloadFilePath = "/etc/ld.so.preload"

// ExactGlobalLDPreloadFileWrite proves that the text one native file-tool call
// writes (nativeFileWrites: a whole-file write, an edit, a multi-edit or a
// patch, whatever the tool calls its arguments) installs a system-wide loader
// injection: an absolute shared-object path in /etc/ld.so.preload, or one
// active `export LD_PRELOAD=/absolute/library.so` line in a direct
// /etc/profile.d shell fragment, in the file the call names or the file an
// existing link reaches (nativeReachedFiles). It retains neither the path nor
// the text.
func ExactGlobalLDPreloadFileWrite(input Input, facts Facts) bool {
	if input.Command != "" || len(input.Argv) != 0 ||
		!facts.Authoritative() || !facts.EnforcementEligible() {
		return false
	}
	writes := nativeFileWrites(input.Tool, input.Args)
	for _, write := range writes {
		for _, file := range nativeWriteFiles(input, facts, writes, write, true) {
			switch {
			case EtcSpelling(file) == globalLDPreloadFilePath:
				if addsGlobalLDPreloadEntry(write) {
					return true
				}
			case ExactGlobalLDPreloadProfilePath(file):
				if addsGlobalLDPreloadExport(write) {
					return true
				}
			}
		}
	}
	return false
}

// addsGlobalLDPreloadEntry reports whether the written text of
// /etc/ld.so.preload is only comments and literal shared-object paths and adds
// a path the text it replaces did not hold.
func addsGlobalLDPreloadEntry(write nativeFileWrite) bool {
	added, ok := globalLDPreloadFileEntries(write.added)
	if !ok || len(added) == 0 {
		return false
	}
	if write.whole {
		return true
	}
	had := map[string]int{}
	for _, entry := range ldPreloadFileTokens(write.replaced) {
		had[entry]++
	}
	for _, entry := range added {
		if had[entry] == 0 {
			return true
		}
		had[entry]--
	}
	return false
}

// addsGlobalLDPreloadExport reports whether the written fragment of a profile
// fragment is the one literal LD_PRELOAD export (and comments) and the text it
// replaces did not already hold that line.
func addsGlobalLDPreloadExport(write nativeFileWrite) bool {
	if !ExactGlobalLDPreloadProfileContent(write.added) {
		return false
	}
	if write.whole {
		return true
	}
	for _, line := range strings.Split(write.added, "\n") {
		line = strings.Trim(line, " \t")
		if !strings.HasPrefix(line, "export ") {
			continue
		}
		for _, had := range strings.Split(write.replaced, "\n") {
			if strings.Trim(had, " \t") == line {
				return false
			}
		}
	}
	return true
}

// globalLDPreloadFileEntries returns the shared-object paths of text that is
// only comments, blank lines and literal absolute shared-object paths.
func globalLDPreloadFileEntries(text string) ([]string, bool) {
	if len(text) > maxCommandBytes || !utf8.ValidString(text) || strings.ContainsRune(text, 0) {
		return nil, false
	}
	var entries []string
	for _, entry := range ldPreloadFileTokens(text) {
		if !exactGlobalLDPreloadSharedObject(entry) {
			return nil, false
		}
		entries = append(entries, entry)
	}
	return entries, true
}

// ldPreloadFileTokens are the whitespace-separated entries of the lines of
// /etc/ld.so.preload text that are not comments.
func ldPreloadFileTokens(text string) []string {
	var tokens []string
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		if line = strings.TrimSpace(line); line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		tokens = append(tokens, strings.Fields(line)...)
	}
	return tokens
}

// ExactGlobalLDPreloadProfilePath accepts only one canonical direct shell
// fragment under /etc/profile.d. Nested paths, templates, and documentation
// files are intentionally outside the proof grammar.
func ExactGlobalLDPreloadProfilePath(value string) bool {
	if value == "" || len(value) > maxScalarBytes || !utf8.ValidString(value) ||
		strings.TrimSpace(value) != value || strings.IndexByte(value, 0) >= 0 ||
		path.Clean(value) != value || hasUnresolvedPathSyntax(value) {
		return false
	}
	value = EtcSpelling(value)
	if !strings.HasPrefix(value, globalLDPreloadProfileDirectory) {
		return false
	}
	leaf := strings.TrimPrefix(value, globalLDPreloadProfileDirectory)
	if leaf == "" || strings.ContainsRune(leaf, '/') || !strings.HasSuffix(leaf, ".sh") {
		return false
	}
	stem := strings.TrimSuffix(leaf, ".sh")
	if stem == "" {
		return false
	}
	for _, character := range stem {
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == '_' || character == '-' || character == '.' {
			continue
		}
		return false
	}
	return true
}

// ExactGlobalLDPreloadProfileContent accepts comments and blank lines plus
// exactly one active, literal `export LD_PRELOAD=/absolute/library.so` line.
// Any additional executable shell content or interpolation causes abstention.
func ExactGlobalLDPreloadProfileContent(content string) bool {
	if content == "" || len(content) > maxCommandBytes || !utf8.ValidString(content) ||
		strings.ContainsAny(content, "\x00\r") {
		return false
	}
	assignmentSeen := false
	for _, rawLine := range strings.Split(content, "\n") {
		line := strings.Trim(rawLine, " \t")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if assignmentSeen || !strings.HasPrefix(line, "export ") {
			return false
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != "export" {
			return false
		}
		name, value, ok := strings.Cut(fields[1], "=")
		if !ok || name != "LD_PRELOAD" {
			return false
		}
		value, ok = exactGlobalLDPreloadLiteral(value)
		if !ok {
			return false
		}
		assignmentSeen = exactGlobalLDPreloadSharedObject(value)
		if !assignmentSeen {
			return false
		}
	}
	return assignmentSeen
}

func exactGlobalLDPreloadLiteral(value string) (string, bool) {
	if len(value) >= 2 && (value[0] == '\'' && value[len(value)-1] == '\'' ||
		value[0] == '"' && value[len(value)-1] == '"') {
		quote := value[0]
		value = value[1 : len(value)-1]
		if strings.ContainsRune(value, rune(quote)) {
			return "", false
		}
	}
	if value == "" || strings.ContainsAny(value, "$`{}()[]*?!\\;|&<> \t\n\r") {
		return "", false
	}
	return value, true
}

func exactGlobalLDPreloadSharedObject(value string) bool {
	if !strings.HasPrefix(value, "/") || path.Clean(value) != value ||
		hasUnresolvedPathSyntax(value) {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == '/' || character == '_' || character == '-' ||
			character == '.' || character == '+' {
			continue
		}
		return false
	}
	base := path.Base(value)
	marker := strings.Index(base, ".so")
	return marker > 0 && (marker+3 == len(base) || base[marker+3] == '.')
}
