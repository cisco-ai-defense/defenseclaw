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
	"fmt"
	"io/fs"
	"time"

	"golang.org/x/sys/unix"
)

// skillChangeStampTamperEvident: an unprivileged user cannot set the inode
// change time back.
const skillChangeStampTamperEvident = true

// skillEntryChangeStamp is the inode change time, inode, link count and
// owner of path. Any write or chmod, and any link or owner change that would
// change whether a SKILL.md is kept as the manifest, moves one of them. It
// also returns the inode change time, for the racy-entry check.
func skillEntryChangeStamp(path string, _ fs.FileInfo) (string, time.Time) {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return "?", time.Time{}
	}
	return fmt.Sprintf("%d.%d:%d:%d:%d:%d", st.Ctim.Sec, st.Ctim.Nsec, st.Dev, st.Ino, st.Nlink, st.Uid),
		time.Unix(int64(st.Ctim.Sec), int64(st.Ctim.Nsec))
}
