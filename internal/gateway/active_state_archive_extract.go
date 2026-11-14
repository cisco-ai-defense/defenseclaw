// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// stateReachFunc returns the judge of one absolute path: it is the active
// state root or a path in it, spelled there or reached through a link
// (followed with the hook's target map first, a managed gateway cannot read
// the home, then the local filesystem when the hook allows it). ok is false
// when the home is not a POSIX one.
func stateReachFunc(facts actionfacts.Facts, request trustedActionRequest) (func(string) bool, bool) {
	home := strings.TrimRight(facts.ActiveHome, "/")
	if !strings.HasPrefix(home, "/") {
		return nil, false
	}
	resolve := stateLinkResolver(request)
	_, inState := stateRootOf(home, resolve)
	spelledRoot := home + "/.defenseclaw"
	fold := runtime.GOOS == "darwin" || runtime.GOOS == "windows"
	spelledInState := func(value string) bool {
		if fold {
			value, spelledRoot := strings.ToLower(value), strings.ToLower(spelledRoot)
			return value == spelledRoot || strings.HasPrefix(value, spelledRoot+"/")
		}
		return value == spelledRoot || strings.HasPrefix(value, spelledRoot+"/")
	}
	return func(full string) bool {
		full = path.Clean(filepath.ToSlash(full))
		if spelledInState(full) {
			return true
		}
		physical, ok := resolve(full)
		if !ok {
			physical, ok = request.ResolvedWriteTargets[hookpaths.DirectoryFactPrefix+full]
		}
		return ok && path.IsAbs(physical) && inState(physical)
	}, true
}

// archiveExtractsIntoState reports an archive extraction (unzip -d, tar -C,
// 7z -o, cpio -D, ditto) whose folder is the active state root or a folder
// in it, or that names a tar or unzip member landing there (tar -xf x.tar -C ~
// .defenseclaw/config.yaml, rel-1-0-10:GAP-0142), spelled there or reached
// through a link: `yes | unzip -q -d ~/proj/evil x.zip` with ~/proj/evil ->
// ~/.defenseclaw replaces config.yaml and hooks/ as a redirect through the
// same link would (GAP-2415). ActionFacts gives an extraction no path fact,
// so it is proved from the shell words (hookpaths.ArchiveExtractionPaths).
// An extraction into the home or a project folder that names no member
// there stays allowed.
func archiveExtractsIntoState(facts actionfacts.Facts, request trustedActionRequest) bool {
	reaches, ok := stateReachFunc(facts, request)
	if !ok {
		return false
	}
	command, known := trustedBashCommandInput(request.Input)
	if !known {
		return false
	}
	for _, full := range hookpaths.ArchiveExtractionPaths(command, facts.CWD, strings.TrimRight(facts.ActiveHome, "/")) {
		if reaches(full) {
			return true
		}
	}
	return false
}

// inlineHandoffStateWrite reports an inline-code interpreter child (python -c
// CODE ARG...) handed a path in the active state: no reader proves the code
// read-only, so every fixed path a runner hands it (direct argv, sudo, env,
// sh -c, a variable) is a possible write of it, and so is a word whose value
// only a runner knows ("$f" of a while read loop) in a command that names
// the state at all (rel-1-0-10:GAP-0365). The runners that rewrite their call
// first (xargs fed by echo or printf, a find, a for loop) reach this as the
// plain call.
func inlineHandoffStateWrite(facts actionfacts.Facts, request trustedActionRequest) bool {
	reaches, ok := stateReachFunc(facts, request)
	if !ok {
		return false
	}
	command, known := trustedBashCommandInput(request.Input)
	if !known {
		return false
	}
	home := strings.TrimRight(facts.ActiveHome, "/")
	paths, dynamic := hookpaths.InlineHandedPaths(command, facts.CWD, home)
	for _, full := range paths {
		if reaches(full) {
			return true
		}
	}
	return dynamic && (request.targetMemo.ActionStateTargetMention(command, request.Input.CWD, request.Input.ActiveHome) ||
		hookpaths.CommandMentionsPath(command, home, home+"/.defenseclaw"))
}
