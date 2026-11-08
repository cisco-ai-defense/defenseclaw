// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"strings"
)

// JoinDirectoryText places a directory that may be relative at the folder a
// call starts in, as text. It is the one way a hook client or a gateway
// joins a workdir or a saved home to a folder: filepath.Join would drop a
// parent step before any link is resolved, which names another folder than
// the file system does when a link comes before the "..". The result is
// resolved component by component, a link before a parent step included, by
// PlaceDirectory (hook clients), pathEvalSymlinks (the late scan) or the
// gateway working-directory resolution.
func JoinDirectoryText(base, dir string) string {
	if filepath.IsAbs(dir) || base == "" {
		return dir
	}
	return base + string(filepath.Separator) + dir
}

// WorkdirCleanedByAgent reports a connector whose agent cleans a tool call
// workdir as text before it starts the process, so the parent step of
// lnk/.. never reaches the file system: Codex exec_command (observed on
// Codex 0.159: workdir "lnk/.." ran in the folder that holds lnk).
func WorkdirCleanedByAgent(connector string) bool {
	return strings.EqualFold(strings.TrimSpace(connector), "codex")
}

// CleanedDirectory places a workdir the way such an agent does: joined to
// the folder the call starts in and cleaned as text.
func CleanedDirectory(base, dir string) string {
	return filepath.Clean(JoinDirectoryText(base, dir))
}

// PlaceDirectory is the absolute folder a call runs in, from the folder it
// starts in (empty for an absolute dir) and the directory it names. A
// directory with a parent step is read as the file system reads it: each
// component is followed, a link before the parent step included, so
// project/lnk/.. is the folder lnk points out of, not project. A directory
// without a parent step is only cleaned, so a folder the caller reached
// through a link keeps the spelling the gateway also sees. A directory the
// file system cannot resolve (it does not exist, so no call runs in it) is
// cleaned as text.
func PlaceDirectory(base, dir string) string {
	text := JoinDirectoryText(base, dir)
	if hasParentStep(text) {
		if real, err := pathEvalSymlinks(text); err == nil {
			return real
		}
	}
	return filepath.Clean(text)
}

func hasParentStep(path string) bool {
	for _, element := range strings.FieldsFunc(path, func(r rune) bool { return r == filepath.Separator || r == 0x2f }) {
		if element == ".." {
			return true
		}
	}
	return false
}
