// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path"
	"slices"
	"strings"
	"unicode/utf8"
)

// nativeAbsoluteTarget returns the lexically cleaned absolute spelling of the
// file a native file-tool call writes. A relative target is resolved against
// the absolute POSIX working directory of the call, as the tool does; without
// one it names no file.
func nativeAbsoluteTarget(target, cwd string) (string, bool) {
	if target == "" || len(target) > maxScalarBytes || !utf8.ValidString(target) ||
		strings.ContainsRune(target, 0) {
		return "", false
	}
	if !strings.HasPrefix(target, "/") {
		if !strings.HasPrefix(cwd, "/") {
			return "", false
		}
		target = cwd + "/" + target
	}
	return path.Clean(target), true
}

// nativeOperandsCoverTarget reports whether the facts of a native file-tool
// call name a write operand for target and no more operands than the call has
// files: a call whose facts carry an operand the call does not write is not
// the call the proof read.
func nativeOperandsCoverTarget(facts Facts, files int, target string) bool {
	operands := facts.OperandPaths()
	if len(operands) == 0 || len(operands) > files {
		return false
	}
	for _, operand := range operands {
		if (operand.Access == PathAccessWrite || operand.Access == PathAccessAppend) &&
			operand.Flavor == PathFlavorPOSIX &&
			EtcSpelling(path.Clean(operand.Resolved)) == EtcSpelling(target) {
			return true
		}
	}
	return false
}

// nativeReachedFiles returns the files a native write to target reaches: the
// target itself and, when the gateway found that the operand naming target is
// reached through an existing link (PathFact.Linked, from the hook client
// evidence or a local lookup), the physical file of each such link. A content
// proof judges the text against every one of them, so a write through a link
// to a protected file gets the verdict the write by the protected name gets.
// A link fact belongs to the operand it was added for (PathFact.LinkedFrom),
// so a call that writes several files judges the text of each write only
// against the files that write reaches.
func nativeReachedFiles(facts Facts, target string) []string {
	files := []string{target}
	if !facts.Authoritative() || !facts.EnforcementEligible() {
		return files
	}
	for _, candidate := range facts.Paths {
		if !candidate.Linked || candidate.Flavor != PathFlavorPOSIX ||
			candidate.Access != PathAccessWrite && candidate.Access != PathAccessAppend ||
			!strings.HasPrefix(candidate.Resolved, "/") ||
			!strings.HasPrefix(candidate.LinkedFrom, "/") ||
			EtcSpelling(path.Clean(candidate.LinkedFrom)) != EtcSpelling(target) {
			continue
		}
		if physical := path.Clean(candidate.Resolved); physical != target {
			files = append(files, physical)
		}
	}
	return files
}

// nativeWriteFiles returns every file a native write may put its text into: the
// file its target names, the physical file of an existing link the facts record
// (nativeReachedFiles), and the files the hook client placed the target on
// (nativeClientReachedFiles). requireOperand is true for a proof that judges the
// lexical target only when the facts carry the operand for it.
func nativeWriteFiles(input Input, facts Facts, writes []nativeFileWrite, write nativeFileWrite, requireOperand bool) []string {
	var files []string
	if target, ok := nativeAbsoluteTarget(write.target, input.CWD); ok {
		switch {
		case nativeOperandsCoverTarget(facts, len(writes), target):
			files = nativeReachedFiles(facts, target)
		case !requireOperand:
			files = []string{target}
		}
	}
	return append(files, nativeClientReachedFiles(input, write.target)...)
}

// nativeClientReachedFiles returns the files a relative or link-named target
// reaches when the gateway has no working directory of its own for the call (a
// managed gateway cannot read the home of the user, so it places nothing and
// follows no link there). The hook client resolved the target as the user and
// keyed its answer by the spelling of the operand in the directory it ran the
// call in (Input.ClientResolvedTargets, Input.ClientWorkingDirectories): the
// answer is the physical file of a link or of a dot-dot path. For a directory
// the client gave no answer for, the target is placed in that directory
// lexically, as the direct name of the file is judged. Nothing here reads the
// file system.
func nativeClientReachedFiles(input Input, target string) []string {
	var files []string
	add := func(file string) {
		if file = path.Clean(file); strings.HasPrefix(file, "/") && !slices.Contains(files, file) {
			files = append(files, file)
		}
	}
	for _, dir := range nativeClientDirectories(input, target) {
		if physical, ok := input.ClientResolvedTargets[clientOperandKey(target, dir)]; ok && strings.HasPrefix(physical, "/") {
			add(physical)
		} else if !strings.HasPrefix(target, "/") {
			add(dir + "/" + target)
		}
	}
	if physical, ok := input.ClientResolvedTargets[target]; ok {
		add(physical)
	}
	return files
}

// nativeClientAnswers returns only the physical files the hook client gave for
// the spelling of target, none when it gave no answer: whether the client could
// tell, apart from where the name lexically falls.
func nativeClientAnswers(input Input, target string) []string {
	var files []string
	add := func(file string) {
		if file = path.Clean(file); strings.HasPrefix(file, "/") && !slices.Contains(files, file) {
			files = append(files, file)
		}
	}
	for _, dir := range nativeClientDirectories(input, target) {
		if physical, ok := input.ClientResolvedTargets[clientOperandKey(target, dir)]; ok {
			add(physical)
		}
	}
	if physical, ok := input.ClientResolvedTargets[target]; ok {
		add(physical)
	}
	return files
}

// nativeClientDirectories is the directories the hook client may have keyed
// its answer for target by: the working directory of the call and the
// directories the client ran it in. A target that is not text the proofs read
// has none.
func nativeClientDirectories(input Input, target string) []string {
	if target == "" || len(target) > maxScalarBytes || !utf8.ValidString(target) ||
		strings.ContainsRune(target, 0) {
		return nil
	}
	dirs := make([]string, 0, 1+len(input.ClientWorkingDirectories))
	for _, dir := range append([]string{input.CWD}, input.ClientWorkingDirectories...) {
		if strings.HasPrefix(dir, "/") && !strings.ContainsRune(dir, 0) {
			dirs = append(dirs, dir)
		}
	}
	return dirs
}

// hasDotDotSegment reports whether a name steps up a directory. The physical
// file such a name reaches depends on the links before the segment, so the
// lexical clean of the name is not that file.
func hasDotDotSegment(name string) bool {
	return slices.Contains(strings.Split(name, "/"), "..")
}

// clientOperandKey is the key the hook client gives a POSIX file operand: the
// dot-dot spelling stays raw until the client has followed links, every other
// spelling is cleaned (OperandPath, with slashes whatever system reads it).
func clientOperandKey(name, dir string) string {
	if !strings.Contains(name, "/../") && !strings.HasSuffix(name, "/..") {
		if !strings.HasPrefix(name, "/") {
			return path.Join(dir, name)
		}
		return path.Clean(name)
	}
	if strings.HasPrefix(name, "/") {
		return name
	}
	return dir + "/" + name
}
