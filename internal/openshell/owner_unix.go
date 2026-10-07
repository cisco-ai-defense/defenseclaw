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

package openshell

import (
	"io/fs"
	"os"
	"os/user"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// ownedByCaller reports whether info belongs to the effective user.
func ownedByCaller(info fs.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Geteuid()
}

// ownedByCallerOrRoot reports whether info belongs to the caller or to
// root, the only users trusted to write gateway registrations.
func ownedByCallerOrRoot(info fs.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && (int(st.Uid) == os.Geteuid() || st.Uid == 0)
}

// ownerName names info's owner: the account name, else "uid N" ("" when
// unknown).
func ownerName(info fs.FileInfo) string {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	uid := strconv.FormatUint(uint64(st.Uid), 10)
	if u, err := user.LookupId(uid); err == nil && u.Username != "" {
		return u.Username
	}
	return "uid " + uid
}

// dirWritable reports whether this process may create entries in dir.
func dirWritable(dir string) bool { return unix.Access(dir, unix.W_OK) == nil }
