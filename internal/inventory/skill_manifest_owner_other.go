// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package inventory

import (
	"io/fs"
	"os"
	"syscall"
)

// skillManifestOwned reports whether the opened SKILL.md may be kept as the
// skill's manifest: a regular file with one link, owned by the owner of the
// skill folder (rootInfo), as the Linux sensor helper requires of a home's
// files. A scan running as root otherwise keeps the text of a hard link to a
// file the user cannot read. The walk read the bytes from this same handle,
// so a swap between the check and the read keeps nothing (GAP-1811).
func skillManifestOwned(file *os.File, rootInfo fs.FileInfo) bool {
	if file == nil || rootInfo == nil {
		return false
	}
	root, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().IsRegular() && st.Nlink == 1 && st.Uid == root.Uid
}

// skillHardLinked reports whether the opened regular file has more than one
// name. A user can hard-link a file only root can read into a skill folder on
// macOS (no protected hard links), and a root scan would then hash it
// (GAP-2146).
func skillHardLinked(file *os.File) bool {
	info, err := file.Stat()
	if err != nil {
		return true // unknown: ask the trust
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return !ok || st.Nlink > 1
}
