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

//go:build linux

package workspace

import (
	"os"

	"golang.org/x/sys/unix"
)

// cloneFile creates dst (which must not exist) sharing src's data blocks
// when the filesystem supports reflinks (btrfs, XFS, bcachefs). It returns
// false, leaving no dst behind, when cloning is unavailable so the caller
// can fall back to a byte copy. Like the darwin version it never follows a
// symlink at src.
func cloneFile(src, dst string) bool {
	in, err := os.OpenFile(src, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return false
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return false
	}
	cerr := unix.IoctlFileClone(int(out.Fd()), int(in.Fd()))
	if closeErr := out.Close(); cerr == nil && closeErr != nil {
		cerr = closeErr
	}
	if cerr != nil {
		_ = os.Remove(dst)
		return false
	}
	return true
}

// exchangeDirs atomically swaps two existing paths (renameat2
// RENAME_EXCHANGE). It fails where the kernel or filesystem cannot, so the
// caller can fall back to two renames.
func exchangeDirs(a, b string) error {
	return unix.Renameat2(unix.AT_FDCWD, a, unix.AT_FDCWD, b, unix.RENAME_EXCHANGE)
}
