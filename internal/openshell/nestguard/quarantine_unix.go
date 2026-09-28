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

//go:build linux || darwin

package nestguard

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func supported() bool { return true }

// quarantine renames dir/.git inside root to dir/<name>. Every directory on
// the way is opened with O_NOFOLLOW relative to its parent, so a symlink the
// agent plants (or swaps in) anywhere on the path makes the quarantine fail
// instead of renaming something outside dir; the final rename never follows
// the .git entry itself either. An existing name is never replaced. It
// returns the name the entry got.
//
// The sandbox runs as the operator's uid, so the agent can take write
// permission off dir to make the rename fail: a dir owned by the guard's
// uid gets write and search permission back for the rename, and its mode
// is restored after it.
//
// A non-zero keepBefore leaves in place (errPreexisting) an entry whose
// status last changed before it: the entry existed before the session,
// which cannot give what it creates or changes an older change time.
func quarantine(root, dir, name string, keepBefore time.Time) (string, error) {
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", root, err)
	}
	if dir != "." {
		for _, part := range strings.Split(dir, "/") {
			if part == "" || part == "." || part == ".." {
				unix.Close(fd)
				return "", fmt.Errorf("invalid directory %q", dir)
			}
			next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			unix.Close(fd)
			if err != nil {
				if errors.Is(err, unix.ENOENT) {
					return "", fs.ErrNotExist
				}
				return "", fmt.Errorf("open %s without following symlinks: %w", dir, err)
			}
			fd = next
		}
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstatat(fd, GitEntry, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return "", fs.ErrNotExist
		}
		return "", err
	}
	if !keepBefore.IsZero() && time.Unix(st.Ctim.Unix()).Before(keepBefore) {
		return "", errPreexisting
	}
	for i := 0; i < 100; i++ {
		candidate := name
		if i > 0 {
			candidate = name + "-" + strconv.Itoa(i)
		}
		err := renameWritable(fd, GitEntry, candidate)
		switch {
		case err == nil:
			return candidate, nil
		case errors.Is(err, unix.EEXIST) || errors.Is(err, unix.ENOTEMPTY):
			continue
		case errors.Is(err, unix.ENOENT):
			return "", fs.ErrNotExist
		default:
			return "", fmt.Errorf("rename %s: %w", GitEntry, err)
		}
	}
	return "", fmt.Errorf("no free quarantine name next to %s/%s", dir, GitEntry)
}

// renameWritable renames from to to inside dirfd. When the directory lacks
// write or search permission and the guard's uid owns it, it gets both for
// the rename and its own mode back afterwards.
func renameWritable(dirfd int, from, to string) error {
	err := renameNoReplace(dirfd, from, to)
	if !errors.Is(err, unix.EACCES) && !errors.Is(err, unix.EPERM) {
		return err
	}
	var st unix.Stat_t
	if unix.Fstat(dirfd, &st) != nil || int(st.Uid) != os.Geteuid() {
		return err
	}
	mode := uint32(st.Mode) & 0o7777
	if mode&0o300 == 0o300 || unix.Fchmod(dirfd, mode|0o300) != nil {
		return err
	}
	err = renameNoReplace(dirfd, from, to)
	// A mode left writable only costs the agent's own restriction.
	_ = unix.Fchmod(dirfd, mode)
	return err
}
