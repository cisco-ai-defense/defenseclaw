// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package local

import (
	"fmt"
	"os"
	"path/filepath"
)

// JSONLPathProblem says, as the end of a sentence about path ("<path> is a
// directory"), why a jsonl destination may not write path, or returns "" for
// a path it may use or cannot inspect. It only reads: the config checks of
// config validate, ensure and Setup run it before anything changes, and the
// gateway names the reason with it when the destination does not open. A
// directory, a link, a device, a folder other accounts can write and an
// existing file other accounts can read or write were refused only at
// gateway start, as runtime_unavailable (GAP-0890, GAP-0908, GAP-1033).
// allowedWriters are further accounts (SIDs or names) that may write the
// folder on Windows, the gateway service account when an administrator
// checks; other platforms ignore them.
func JSONLPathProblem(path string, allowedWriters ...string) string {
	if info, err := os.Lstat(path); err == nil {
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			return "is a symbolic link"
		case info.IsDir():
			return "is a directory"
		case !info.Mode().IsRegular():
			return "is not a regular file (a device, pipe or socket)"
		}
		if problem := jsonlFileProblem(info); problem != "" {
			return problem
		}
		if problem := jsonlACLProblem(path); problem != "" {
			return problem
		}
	}
	folder := filepath.Dir(path)
	info, err := os.Lstat(folder)
	if err != nil {
		// The gateway creates a missing folder. On Windows it gets what the
		// nearest existing folder passes on to new subfolders, and the
		// gateway refused it at open when that lets another account write
		// it; the check passed with the folder still missing (GAP-1381).
		ancestor, depth := filepath.Dir(folder), 1
		for ancestor != filepath.Dir(ancestor) {
			if _, statErr := os.Lstat(ancestor); statErr == nil {
				return jsonlMissingFolderProblem(folder, ancestor, depth, allowedWriters)
			}
			ancestor, depth = filepath.Dir(ancestor), depth+1
		}
		return ""
	}
	switch {
	case info.Mode()&os.ModeSymlink != 0:
		return fmt.Sprintf("is in %s, a symbolic link", folder)
	case !info.IsDir():
		return fmt.Sprintf("is in %s, which is not a folder", folder)
	}
	return jsonlFolderProblem(folder, info, allowedWriters)
}
