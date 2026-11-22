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
	"bytes"
	"io"
	"io/fs"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// skillManifestOwned reports whether the SKILL.md at path, whose bytes the
// hash walk read as data, may be kept as the skill's manifest: a regular
// file with one link, owned by the owner of the skill folder (rootInfo), as
// the Linux sensor helper requires of a home's files. A scan running as root
// otherwise keeps the text of a hard link to a file the user cannot read.
// The checks run on the opened file and its bytes must equal data, so a
// swap between the two reads keeps nothing (GAP-1811).
func skillManifestOwned(path string, rootInfo fs.FileInfo, data []byte) bool {
	root, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return false
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != root.Uid {
		return false
	}
	got, err := io.ReadAll(io.LimitReader(file, int64(len(data))+1))
	return err == nil && bytes.Equal(got, data)
}
