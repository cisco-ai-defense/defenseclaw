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
// directory, a link, a device and a folder other accounts can write were
// refused only at gateway start, as runtime_unavailable (GAP-0890,
// GAP-0908). allowedWriters are further accounts (SIDs or names) that may
// write the folder on Windows, the gateway service account when an
// administrator checks; other platforms ignore them.
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
	}
	folder := filepath.Dir(path)
	info, err := os.Lstat(folder)
	if err != nil {
		return "" // the gateway creates a missing folder, owner-only
	}
	switch {
	case info.Mode()&os.ModeSymlink != 0:
		return fmt.Sprintf("is in %s, a symbolic link", folder)
	case !info.IsDir():
		return fmt.Sprintf("is in %s, which is not a folder", folder)
	}
	return jsonlFolderProblem(folder, info, allowedWriters)
}
