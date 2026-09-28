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

import (
	"errors"
	"strconv"

	"golang.org/x/sys/unix"
)

// dirOpenFlags opens a directory on the quarantine path for lookups only
// (O_PATH), which needs search permission on its parent but no read
// permission on the directory itself. With O_NOFOLLOW a symlink opens as
// the link, which O_DIRECTORY and quarantine's type check refuse.
const dirOpenFlags = unix.O_PATH | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC

// fchmodDir changes the mode of the directory fd refers to. fchmod refuses
// an O_PATH descriptor; its /proc/self/fd link names exactly that inode.
func fchmodDir(fd int, mode uint32) error {
	return unix.Fchmodat(unix.AT_FDCWD, "/proc/self/fd/"+strconv.Itoa(fd), mode, 0)
}

// renameNoReplace renames from to to inside the directory dirfd, failing
// with EEXIST when to exists. Filesystems without RENAME_NOREPLACE get a
// check-then-rename, which only races with a name the agent would have to
// guess to the second.
func renameNoReplace(dirfd int, from, to string) error {
	err := unix.Renameat2(dirfd, from, dirfd, to, unix.RENAME_NOREPLACE)
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) {
		var st unix.Stat_t
		if unix.Fstatat(dirfd, to, &st, unix.AT_SYMLINK_NOFOLLOW) == nil {
			return unix.EEXIST
		}
		return unix.Renameat(dirfd, from, dirfd, to)
	}
	return err
}
