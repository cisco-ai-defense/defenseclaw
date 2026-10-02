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

package nestguard

import "golang.org/x/sys/unix"

// dirOpenFlags opens a directory on the quarantine path; O_NOFOLLOW makes
// a symlink fail to open.
const dirOpenFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC

// fchmodDir changes the mode of the directory fd refers to.
func fchmodDir(fd int, mode uint32) error { return unix.Fchmod(fd, mode) }

// renameNoReplace renames from to to inside the directory dirfd, failing
// with EEXIST when to exists (renameatx_np RENAME_EXCL).
func renameNoReplace(dirfd int, from, to string) error {
	return unix.RenameatxNp(dirfd, from, dirfd, to, unix.RENAME_EXCL)
}
