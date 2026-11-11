// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"strings"
)

// ResolveWriteTargetPastMissingStepUps places an absolute raw spelling whose
// dot-dot steps leave a directory that does not exist (sub/../notes.txt with
// no sub). A file tool or an apply_patch header creates the directories on the
// way of the file it writes, so a missing directory becomes a plain directory
// and its dot-dot is the directory above it: the file is the cleaned name.
// Each "missing/.." pair is removed and the rest is walked as ResolveWriteTarget
// walks it, so a dot-dot that leaves an existing directory (a link among them)
// keeps its physical meaning, and a cleaned name that is a protected file is
// still found by the caller. changed is false when no pair was removed, and
// the caller keeps the answer of the raw walk.
func ResolveWriteTargetPastMissingStepUps(path string) (resolved string, ok, changed bool) {
	if !filepath.IsAbs(path) {
		return "", false, false
	}
	volume := filepath.VolumeName(path)
	separator := string(filepath.Separator)
	join := func(parts []string) string { return volume + separator + strings.Join(parts, separator) }
	var kept []string
	for _, part := range strings.Split(filepath.ToSlash(strings.TrimPrefix(path, volume)), "/") {
		switch part {
		case "", ".":
			continue
		case "..":
			if n := len(kept); n > 0 && kept[n-1] != ".." {
				if _, err := pathLstat(join(kept)); os.IsNotExist(err) {
					kept, changed = kept[:n-1], true
					continue
				}
			}
		}
		kept = append(kept, part)
	}
	if !changed {
		return "", false, false
	}
	resolved, ok = ResolveWriteTarget(join(kept))
	return resolved, ok, true
}
