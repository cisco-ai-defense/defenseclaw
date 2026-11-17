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
// when the home is neither a POSIX one nor, on a native Windows gateway, a
// drive one.
//
// A drive home (C:\Users\x) is judged in its slash spelling: the extraction
// and inline hand-off readers place a Git Bash word (~/.defenseclaw, $HOME/x,
// a relative folder) with filepath against the Windows home and cwd, so a
// tar -C or unzip -d into the state and a python -c hand-off of a state file
// were never judged on a Windows home (rel-1-0-10:GAP-0154, GAP-1173).
func stateReachFunc(facts actionfacts.Facts, request trustedActionRequest) (func(string) bool, bool) {
	home := strings.TrimRight(facts.ActiveHome, "/")
	drive := false
	if !strings.HasPrefix(home, "/") {
		slashed := strings.TrimRight(filepath.ToSlash(home), "/")
		if runtime.GOOS != "windows" || !actionfacts.DriveSlashPath(slashed) {
			return nil, false
		}
		home, drive = slashed, true
	}
	resolve := stateLinkResolver(request)
	spelledRoot := home + "/.defenseclaw"
	fold := runtime.GOOS == "darwin" || runtime.GOOS == "windows"
	under := func(value, root string) bool {
		if fold {
			value, root = strings.ToLower(value), strings.ToLower(root)
		}
		return value == root || strings.HasPrefix(value, root+"/")
	}
	var inState func(string) bool
	if drive {
		// The physical state root and the physical path of a link are drive
		// paths; both are compared in the slash spelling.
		root, _ := stateRootOf(filepath.FromSlash(home), resolve)
		root = path.Clean(filepath.ToSlash(root))
		inState = func(value string) bool {
			return under(path.Clean(filepath.ToSlash(value)), root)
		}
	} else {
		_, inState = stateRootOf(home, resolve)
	}
	return func(full string) bool {
		full = path.Clean(filepath.ToSlash(full))
		if under(full, spelledRoot) {
			return true
		}
		lookup := full
		if drive {
			lookup = filepath.FromSlash(full)
		}
		physical, ok := resolve(lookup)
		if !ok {
			physical, ok = request.ResolvedWriteTargets[hookpaths.DirectoryFactPrefix+full]
		}
		absolute := path.IsAbs(physical) || drive && actionfacts.DriveSlashPath(filepath.ToSlash(physical))
		return ok && absolute && inState(physical)
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
