// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path"
	"path/filepath"
	"strings"
)

// POSIXUnrestrictedSudoersGrantWriteFact is a value-free proof that one native
// file-tool call puts a literal unrestricted passwordless grant into the main
// sudoers file or a direct drop-in of /etc/sudoers.d.
type POSIXUnrestrictedSudoersGrantWriteFact struct{}

var exactUnrestrictedSudoersGrantLine = lazyMustCompile(
	`^(%?[A-Za-z_][A-Za-z0-9_.-]*|ALL)[\t ]+ALL[\t ]*=[\t ]*\([\t ]*ALL(?:[\t ]*:[\t ]*ALL)?[\t ]*\)[\t ]+NOPASSWD[\t ]*:[\t ]*ALL[\t ]*$`,
)

// ExactPOSIXUnrestrictedSudoersGrantWrite reports only the reviewed structured
// write proof. Unstructured shell writers are deliberately excluded.
func ExactPOSIXUnrestrictedSudoersGrantWrite(facts Facts) bool {
	return facts.Authoritative() && facts.EnforcementEligible() &&
		len(facts.POSIXUnrestrictedSudoersGrantWrites) == 1
}

// projectPOSIXUnrestrictedSudoersGrantWrites reads the text a native file tool
// writes however that tool names its arguments (nativeCallWrites: the native
// tool call, or the apply_patch envelope of a shell here-document), so a grant
// is one fact for every connector write, edit, multi-edit and patch call, not
// only for one argument spelling. The text of a file tool is literal: no shell
// expands it, so a template-looking character elsewhere in the file cannot
// hide a grant line.
func projectPOSIXUnrestrictedSudoersGrantWrites(
	input Input,
	facts Facts,
) []POSIXUnrestrictedSudoersGrantWriteFact {
	if len(input.Argv) != 0 ||
		(!mayNameSudoers([]byte(input.CWD)) && !mayNameSudoers(input.Args) &&
			!mayNameSudoers([]byte(input.Command)) &&
			!resolvesToSudoersTarget(input.ClientResolvedTargets)) {
		return nil
	}
	writes, _ := nativeCallWrites(input, facts)
	for _, write := range writes {
		if (sudoersWriteTargetInCWD(write.target, input.CWD) ||
			clientResolvedSudoersTarget(write.target, input.CWD, input.ClientWorkingDirectories, input.ClientResolvedTargets)) &&
			addsUnrestrictedSudoersGrant(write.added, write.replaced) {
			return []POSIXUnrestrictedSudoersGrantWriteFact{{}}
		}
	}
	return nil
}

// resolvesToSudoersTarget is the cheap test that keeps an ordinary call from
// being decoded when the hook client placed none of its paths on a sudoers
// file: a link named anything can lead to one.
func resolvesToSudoersTarget(resolved map[string]string) bool {
	for _, physical := range resolved {
		if exactSudoersWriteTarget(physical) {
			return true
		}
	}
	return false
}

// clientResolvedSudoersTarget reports whether the hook client, resolving the
// write target as the user, placed it on /etc/sudoers or a direct child of
// /etc/sudoers.d: a link of any name to such a file is that file. The client
// keys its answer by OperandPath of the directory it was given, so a ./ or
// doubled-slash spelling is asked by the cleaned path while a dot-dot spelling
// keeps its raw form. That directory is asked in each spelling the gateway
// knows: its own (the resolved project) and the clients (clientDirs), which
// differ when the project is reached through a link.
func clientResolvedSudoersTarget(target, cwd string, clientDirs []string, resolved map[string]string) bool {
	_, ok := clientResolvedTargetWhere(target, cwd, clientDirs, resolved, exactSudoersWriteTarget)
	return ok
}

// clientResolvedTargetWhere returns the first answer of the hook client for a
// write target, in every spelling the client may have keyed it by, that accept
// takes: the physical file of a link, or for a directory the user cannot open
// the file its link text leads to. A content proof that reads the call text
// before the facts carry a link fact asks it, so a link of any name is judged
// by the file it leads to, as the direct name is.
func clientResolvedTargetWhere(target, cwd string, clientDirs []string, resolved map[string]string, accept func(string) bool) (string, bool) {
	if len(resolved) == 0 || target == "" {
		return "", false
	}
	for _, dir := range append([]string{cwd}, clientDirs...) {
		for _, key := range []string{OperandPath(target, dir), posixOperandPath(target, dir)} {
			if physical := resolved[key]; accept(physical) {
				return physical, true
			}
		}
	}
	if physical := resolved[target]; accept(physical) {
		return physical, true
	}
	return "", false
}

// posixOperandPath is OperandPath for a client that keys POSIX paths with
// slashes whatever system the gateway runs on: the sudoers files are POSIX
// paths, and a client that placed a link on one (an agent running in WSL, a
// POSIX client of a Windows gateway) keys the operand that way. On a POSIX
// host it equals OperandPath. Path semantics are decided by the form of the
// path, not by the gateway system, so the proof does not depend on the OS
// that reads it.
func posixOperandPath(name, cwd string) string {
	absolute := func(value string) bool { return strings.HasPrefix(value, "/") }
	if !strings.Contains(name, "/../") && !strings.HasSuffix(name, "/..") {
		if !absolute(name) && absolute(cwd) {
			return path.Join(cwd, name)
		}
		return path.Clean(name)
	}
	if absolute(name) || !absolute(cwd) {
		return name
	}
	return cwd + "/" + name
}

// OperandPath is the key the hook client gives a file operand in its path
// answers. It preserves dot-dot until link resolution, because filepath.Join
// would erase a directory link before the following dot-dot, and cleans every
// other spelling (./, doubled slashes, a trailing slash).
func OperandPath(name, cwd string) string {
	// Keep the canonical spelling for ordinary operands. Only dot-dot needs a
	// raw spelling until the component walk has followed links.
	if !strings.Contains(filepath.ToSlash(name), "/../") &&
		!strings.HasSuffix(filepath.ToSlash(name), "/..") {
		if !filepath.IsAbs(name) && filepath.IsAbs(cwd) {
			return filepath.Join(cwd, name)
		}
		return filepath.Clean(name)
	}
	if filepath.IsAbs(name) || !filepath.IsAbs(cwd) {
		return name
	}
	return cwd + string(filepath.Separator) + name
}

// mayNameSudoers is the cheap test that keeps an ordinary file-tool call from
// being decoded a second time: a target of the sudoers files holds the word
// sudoers in some letter case, or a \\u escape that could spell a letter of it.
// It is asked of the arguments and of the working directory: a relative target
// of a call made from /etc/sudoers.d names the word only in the directory, and
// the word cannot be split between the two because a slash joins them.
func mayNameSudoers(args []byte) bool {
	const word = "sudoers"
	for i := 0; i < len(args); i++ {
		if args[i] == '\\' && i+1 < len(args) && args[i+1] == 'u' {
			return true
		}
		if i+len(word) > len(args) {
			continue
		}
		match := true
		for j := 0; j < len(word); j++ {
			if args[i+j]|0x20 != word[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// addsUnrestrictedSudoersGrant reports whether added holds an unrestricted
// grant line that replaced does not already hold: an edit that keeps a grant
// the file had, or removes one, adds none.
func addsUnrestrictedSudoersGrant(added, replaced string) bool {
	if len(added) > maxCommandBytes || len(replaced) > maxCommandBytes {
		return false
	}
	had := map[string]int{}
	for _, line := range unrestrictedSudoersGrantLines(replaced) {
		had[line]++
	}
	for _, line := range unrestrictedSudoersGrantLines(added) {
		if had[line] == 0 {
			return true
		}
		had[line]--
	}
	return false
}

func unrestrictedSudoersGrantLines(text string) []string {
	if text == "" || strings.ContainsRune(text, 0) {
		return nil
	}
	var grants []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimLeft(strings.TrimSuffix(line, "\r"), "\t ")
		// root already runs everything, so its own grant is ordinary whatever
		// whitespace separates it from the host field.
		if exactUnrestrictedSudoersGrantLine.MatchString(line) &&
			strings.Fields(line)[0] != "root" {
			grants = append(grants, line)
		}
	}
	return grants
}

// sudoersWriteTargetInCWD resolves a relative target against the absolute
// POSIX working directory of the call, as the tool does, and reports whether
// the file is a sudoers write target.
func sudoersWriteTargetInCWD(target, cwd string) bool {
	if target == "" || len(target) > maxScalarBytes || strings.ContainsRune(target, 0) {
		return false
	}
	if !strings.HasPrefix(target, "/") {
		if !strings.HasPrefix(cwd, "/") {
			return false
		}
		target = cwd + "/" + target
	}
	return exactSudoersWriteTarget(target)
}

// exactSudoersWriteTarget reports /etc/sudoers and each direct child of
// /etc/sudoers.d after lexical cleaning and with the macOS physical
// /private/etc spelling. On macOS, where the volume folds letter case, any
// letter case names the file; on a host that keeps case, /ETC/SUDOERS.D/x is a
// different path that sudo does not read. A path nested below the drop-in
// directory is not read by sudo and is not a target.
func exactSudoersWriteTarget(value string) bool {
	if !strings.HasPrefix(value, "/") {
		return false
	}
	if HostLinksEtcToPrivate {
		value = strings.ToLower(value)
	}
	value = EtcSpelling(path.Clean(value))
	if value == "/etc/sudoers" {
		return true
	}
	const prefix = "/etc/sudoers.d/"
	child := strings.TrimPrefix(value, prefix)
	return child != value && child != "" && !strings.Contains(child, "/")
}
