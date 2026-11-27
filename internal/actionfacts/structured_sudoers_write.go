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
		if sudoersWriteTarget(input, write.target) &&
			addsUnrestrictedSudoersGrant(write.added, write.replaced) {
			return []POSIXUnrestrictedSudoersGrantWriteFact{{}}
		}
	}
	return nil
}

// sudoersWriteTarget reports whether a native write reaches a sudoers file. A
// name that steps up a directory is the file the client answered with when it
// gave one: the lexical clean of such a name is no file the write reaches, so a
// file reached through a link is judged by its own place in both directions
// (a link to a sudoers file is that file, and an ordinary file whose lexical
// name cleans to a sudoers path is not).
func sudoersWriteTarget(input Input, target string) bool {
	if answers := nativeDotDotAnswers(input, target); len(answers) != 0 {
		for _, answer := range answers {
			if exactSudoersWriteTarget(answer) {
				return true
			}
		}
		return false
	}
	return sudoersWriteTargetInCWD(target, input.CWD) ||
		clientResolvedSudoersTarget(target, input.CWD, input.ClientWorkingDirectories, input.ClientResolvedTargets)
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
		for _, key := range []string{OperandPath(target, dir), posixOperandPath(target, dir), clientOperandKey(target, dir)} {
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
//
// Every dot-dot step is applied as text only where the kernel applies it to
// the same folder, in one walk for every spelling (rel-1-0-10:GAP-1648):
//   - a step in front of every name of a relative operand (../x, ./../x,
//     .././../x) climbs from the supplied directory while that directory has
//     no link in its path, also when it does not exist yet (a directory that
//     pushd or cd has not entered);
//   - a step after a name, and every step of an absolute operand ($HOME/..,
//     /home/../alice/.claude, proj/../.claude), climbs only from a directory
//     that exists with no link in its path: the clean join is then the path
//     the kernel opens. A name that does not exist yet (a link the same
//     command creates) or a directory reached through a link keeps the whole
//     spelling raw, for the component walk that follows links.
//
// Before, an absolute operand kept every step raw, so a find root such as
// $HOME/../<home>/.claude reached none of the hook files find ~/.claude
// reaches.
func OperandPath(name, cwd string) string {
	if !hasDotDotStep(filepath.ToSlash(name)) {
		if !filepath.IsAbs(name) && filepath.IsAbs(cwd) {
			return filepath.Join(cwd, name)
		}
		return filepath.Clean(name)
	}
	if filepath.IsAbs(name) {
		if clean, ok := applyDotDotSteps("", name); ok {
			return clean
		}
		return name
	}
	if !filepath.IsAbs(cwd) {
		return name
	}
	if clean, ok := applyDotDotSteps(cwd, name); ok {
		return clean
	}
	return cwd + string(filepath.Separator) + name
}

// maxOperandDotDotSteps bounds the link probes one operand may cost: every
// dot-dot step of it, leading or not, is one; an operand with more stays raw.
const maxOperandDotDotSteps = 16

// operandLinkProbe reports a directory whose path, or the longest existing
// part of it, passes through a link. operandPlainDirProbe reports a directory
// that exists, is a directory and has no link in its path. The defaults see
// no link and no directory: the probes read the file system through the
// bounded readers of the hook path package, which installs them
// (SetOperandLinkProbe, SetOperandPlainDirProbe) in the client and in the
// gateway alike, so both key an operand the same way.
var (
	operandLinkProbe     = func(string) bool { return false }
	operandPlainDirProbe = func(string) bool { return false }
)

// SetOperandLinkProbe installs the link probe OperandPath asks. It is called
// once from an init function.
func SetOperandLinkProbe(probe func(dir string) bool) { operandLinkProbe = probe }

// SetOperandPlainDirProbe installs the existing-directory probe OperandPath
// asks for a dot-dot step after a name. It is called once from an init
// function.
func SetOperandPlainDirProbe(probe func(dir string) bool) { operandPlainDirProbe = probe }

// hasDotDotStep reports a slash-separated operand with a ".." component.
func hasDotDotStep(slashed string) bool {
	for _, part := range strings.Split(slashed, "/") {
		if part == ".." {
			return true
		}
	}
	return false
}

// applyDotDotSteps walks name from base (an absolute name: base is empty and
// the walk starts at its root) and applies each ".." step as text when the
// kernel applies it to the same folder (see OperandPath). ok is false when a
// step must stay raw.
func applyDotDotSteps(base, name string) (string, bool) {
	slashed := filepath.ToSlash(name)
	prefix, named := filepath.Clean(base), false
	if base == "" {
		volume := filepath.VolumeName(name)
		prefix, named = volume+string(filepath.Separator), true
		slashed = filepath.ToSlash(name[len(volume):])
	}
	steps := 0
	for _, part := range strings.Split(slashed, "/") {
		switch part {
		case "", ".":
		case "..":
			if steps++; steps > maxOperandDotDotSteps {
				return "", false
			}
			if named && !operandPlainDirProbe(prefix) || !named && operandLinkProbe(prefix) {
				return "", false
			}
			prefix = filepath.Dir(prefix)
		default:
			prefix, named = filepath.Join(prefix, part), true
		}
	}
	return prefix, true
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
