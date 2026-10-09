//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package kernelpolicy

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// pathTrustedFor resolves path one element at a time, following symbolic
// links as the kernel does, and admits it only when every directory it passes
// through, every link it follows and the final entry are owned by root or
// uid, and no directory or final entry is writable by group or others. No
// other account can then change what path names between the check and its
// use. It is the rule the enumerator applies to agent installs outside a
// user's home (enterprisehooks unixPathTrustedFor), on Linux.
func pathTrustedFor(path string, uid int) bool {
	if !filepath.IsAbs(path) {
		return false
	}
	const maxLinks = 40
	trusted := func(info os.FileInfo, checkMode bool) bool {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return false
		}
		if st.Uid != 0 && int64(st.Uid) != int64(uid) {
			return false
		}
		return !checkMode || info.Mode().Perm()&0o022 == 0
	}
	links := 0
	resolved := "/"
	remaining := strings.Split(strings.TrimPrefix(filepath.Clean(path), "/"), "/")
	for len(remaining) > 0 {
		element := remaining[0]
		remaining = remaining[1:]
		if element == "" || element == "." {
			continue
		}
		if element == ".." {
			resolved = filepath.Dir(resolved)
			continue
		}
		next := filepath.Join(resolved, element)
		info, err := os.Lstat(next)
		if err != nil {
			return false
		}
		if info.Mode()&os.ModeSymlink != 0 {
			links++
			if links > maxLinks || !trusted(info, false) {
				return false
			}
			target, err := os.Readlink(next)
			if err != nil {
				return false
			}
			if filepath.IsAbs(target) {
				resolved = "/"
			}
			remaining = append(strings.Split(strings.TrimPrefix(target, "/"), "/"), remaining...)
			continue
		}
		// Directories (every element but the last) and the final entry must
		// not be writable by group or others.
		if !trusted(info, info.IsDir() || len(remaining) == 0) {
			return false
		}
		resolved = next
	}
	return true
}

// rootOwnedPrivate reports whether a file is owned by root and writable by
// nobody but its owner.
func rootOwnedPrivate(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0 && info.Mode().Perm()&0o022 == 0
}
