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

// archiveExtractsIntoState reports an archive extraction (unzip -d, tar -C,
// 7z -o, cpio -D, ditto) whose folder is the active state root or a folder
// in it, spelled there or reached through a link: `yes | unzip -q -d
// ~/proj/evil x.zip` with ~/proj/evil -> ~/.defenseclaw replaces
// config.yaml and hooks/ as a redirect through the same link would
// (GAP-2415). ActionFacts gives an extraction no path fact, so it is
// proved from the shell words (hookpaths.ArchiveExtractionFolders); the folder is followed through links with
// the hook's target map first (a managed gateway cannot read the home),
// then the local filesystem when the hook allows it. An extraction into
// the home or a project folder stays allowed.
func archiveExtractsIntoState(facts actionfacts.Facts, request trustedActionRequest) bool {
	home := strings.TrimRight(facts.ActiveHome, "/")
	if !strings.HasPrefix(home, "/") {
		return false
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
	command, known := trustedBashCommandInput(request.Input)
	if !known {
		return false
	}
	for _, full := range hookpaths.ArchiveExtractionFolders(command, facts.CWD, home) {
		full = path.Clean(filepath.ToSlash(full))
		if spelledInState(full) {
			return true
		}
		physical, ok := resolve(full)
		if !ok {
			physical, ok = request.ResolvedWriteTargets[hookpaths.DirectoryFactPrefix+full]
		}
		if ok && path.IsAbs(physical) && inState(physical) {
			return true
		}
	}
	return false
}
