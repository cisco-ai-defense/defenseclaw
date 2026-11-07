//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"os"
	"path/filepath"
	"syscall"
)

func writeOpenCodeServiceConfig(_ string, path string, data []byte) error {
	return writePrivateUserFile(path, data)
}

// checkOpenCodeServiceConfigFolders reports whether the account's .config or
// .config/opencode folder is a link (the stow layout). A write still refuses a
// link in place of the opencode folder; a port that already matches needs no
// write, so the link is accepted only if openCodeServiceFileShared finds the
// file it leads to private to the account.
func checkOpenCodeServiceConfigFolders(home, path string) (linked bool, err error) {
	for _, dir := range []string{filepath.Join(home, ".config"), filepath.Dir(path)} {
		info, err := os.Lstat(dir)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return false, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			linked = true
		}
	}
	return linked, nil
}

// openCodeServiceFileShared reports a service.json another account can
// write: a group or other write bit, and, when a link leads to it, a file the
// account does not own or a folder another account can write. The write
// replaces a shared regular file with a 0600 copy and refuses a link.
func openCodeServiceFileShared(path string, linked bool) bool {
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm()&0o022 != 0 {
		return true
	}
	if !linked {
		return false
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return true
	}
	file, err := os.Stat(resolved)
	dir, dirErr := os.Stat(filepath.Dir(resolved))
	if err != nil || dirErr != nil || file.Mode().Perm()&0o022 != 0 || dir.Mode().Perm()&0o022 != 0 {
		return true
	}
	stat, ok := file.Sys().(*syscall.Stat_t)
	return !ok || int(stat.Uid) != os.Geteuid()
}
