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

package connector

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// pluginGetUID is overridable for tests. Returns the effective UID of
// the running process. The default delegates to os.Getuid().
var pluginGetUID = os.Getuid

// pluginOwnerUID extracts the owner UID from a FileInfo. ok is false on a
// filesystem that does not expose a unix stat (should not happen on unix).
func pluginOwnerUID(info os.FileInfo) (uint32, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return stat.Uid, true
}

// pluginInodeIdentity returns the device and inode numbers for a FileInfo so
// the open-then-Fstat path can detect a directory entry that was swapped
// between Lstat and Open. ok is false on a non-unix filesystem.
func pluginInodeIdentity(info os.FileInfo) (dev, ino uint64, ok bool) {
	stat, k := info.Sys().(*syscall.Stat_t)
	if !k {
		return 0, 0, false
	}
	return uint64(stat.Dev), uint64(stat.Ino), true
}

// validatePluginOwner verifies the plugin file is owned by the same UID as
// the running process. This prevents a hostile user on a shared host from
// dropping a plugin that gets loaded with the daemon's privileges.
func validatePluginOwner(soPath string) error {
	info, err := os.Lstat(soPath)
	if err != nil {
		return fmt.Errorf("stat %s: %w", soPath, err)
	}
	return validatePluginOwnerFromInfo(soPath, info)
}

// validatePluginOwnerFromInfo is the FileInfo-driven variant of
// validatePluginOwner. The TOCTOU-hardened load path already holds an
// authoritative FileInfo from the open fd's Fstat, so it verifies ownership
// against that rather than re-stating the path (which could observe a
// different inode after a swap).
func validatePluginOwnerFromInfo(soPath string, info os.FileInfo) error {
	uid, ok := pluginOwnerUID(info)
	if !ok {
		return errors.New("could not extract owner UID from FileInfo (non-unix FS?)")
	}
	want := uint32(pluginGetUID())
	if uid != want {
		return fmt.Errorf("%s owner uid=%d does not match running process uid=%d", soPath, uid, want)
	}
	return nil
}
