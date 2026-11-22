// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path"
	"runtime"
	"strings"
)

// HomePlaceOwnerOnly reports a place that only its owner can enter or read, as
// the file system shows it now: the place itself when it exists (a link is
// followed), else the nearest folder above it that does, with no group or
// other permission bit. A copy keeps the mode of its source and a folder a
// command makes sits below the one that exists, so that one decides who can
// reach the copy. What cannot be read (nothing of the path exists on this
// host, an error other than a missing name, a Windows path, whose access is no
// mode) is not proven private (rel-1-0-10:GAP-0018, GAP-0710).
func HomePlaceOwnerOnly(value string) bool {
	if runtime.GOOS == "windows" || value == "" {
		return false
	}
	existing := path.Clean(value)
	for {
		info, err := pathLstat(existing)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				if info, err = pathStat(existing); err != nil {
					return false
				}
			}
			return info.Mode().Perm()&0o077 == 0
		}
		if !os.IsNotExist(err) {
			return false
		}
		parent := path.Dir(existing)
		if parent == existing || parent == "." {
			return false
		}
		existing = parent
	}
}

// PrivateHomePlace reports a place inside home, outside its SSH folder, whose
// existing part, links followed, stays inside home and outside the SSH folder
// too, and that only its owner can enter or read (HomePlaceOwnerOnly); a part
// that does not exist yet is only a name. Only a missing name (ENOENT) is a
// part a command makes; any other error proves nothing about who can reach the
// place (rel-1-0-10:GAP-0855). It is the destination of a copy of the user's
// own SSH folder content that alerts and does not block (rel-1-0-10:GAP-0018).
func PrivateHomePlace(value, home string) bool {
	value, home = path.Clean(value), strings.TrimRight(home, "/")
	if home == "" || !homePathWithin(value, home) || homePathWithin(value, home+"/.ssh") {
		return false
	}
	existing := value
	for {
		_, err := pathLstat(existing)
		if err == nil {
			break
		}
		if !os.IsNotExist(err) || existing == home || !homePathWithin(existing, home) {
			return false
		}
		existing = path.Dir(existing)
	}
	realHome, err := pathEvalSymlinks(home)
	if err != nil {
		return false
	}
	resolved, err := pathEvalSymlinks(existing)
	if err != nil {
		return false
	}
	return homePathWithin(resolved, realHome) && !homePathWithin(resolved, realHome+"/.ssh") && HomePlaceOwnerOnly(resolved)
}

func homePathWithin(value, parent string) bool {
	value = strings.TrimRight(value, "/")
	parent = strings.TrimRight(parent, "/")
	return value == parent || strings.HasPrefix(value, parent+"/")
}
