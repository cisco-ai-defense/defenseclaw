// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package winpath

import "path/filepath"

// LongName returns the long-name spelling of path when path names an
// existing file through 8.3 short names (C:\PROGRA~1\...\DEFENS~1.EXE), and
// path unchanged otherwise. The long spelling must name the same object by
// the same names (SameNamedFile), so a short name is only ever replaced by
// the name of the file it already is. A junction, link or other file keeps
// its own spelling, and a lookup that does not answer within its budget
// keeps path.
//
// A process started by an 8.3 alias of its image sees that alias from
// os.Executable. The managed hook compares its own image to the installed
// one through it, so it spells itself by the long name first (GAP-2243).
func LongName(path string) string {
	long, ok := longPathName(filepath.FromSlash(path))
	if !ok || long == path || !SameNamedFile(path, long) {
		return path
	}
	return long
}
