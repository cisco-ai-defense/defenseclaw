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
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func supported() bool { return true }

// quarantine renames dir/.git inside root to dir/<name>. Every directory on
// the way is opened with O_NOFOLLOW relative to its parent, so a symlink the
// agent plants (or swaps in) anywhere on the path makes the quarantine fail
// instead of renaming something outside dir; the final rename never follows
// the .git entry itself either. An existing name is never replaced. It
// returns the name the entry got.
func quarantine(root, dir, name string) (string, error) {
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
	for i := 0; i < 100; i++ {
		candidate := name
		if i > 0 {
			candidate = name + "-" + strconv.Itoa(i)
		}
		err := renameNoReplace(fd, GitEntry, candidate)
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
