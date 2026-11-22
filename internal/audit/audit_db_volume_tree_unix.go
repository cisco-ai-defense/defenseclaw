//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// ReclaimOwnTree removes group and other access (and the setgid bit) from
// dir and every directory and regular file under it that the process
// account owns. Kubernetes applies a pod's fsGroup to a volume on every
// mount: with the default fsGroupChangePolicy it makes every directory
// 2770 and every file 0660 under the volume, so a store directory the
// process created 0700 comes back group-writable after a restart and the
// audit store refuses it (EKS with EBS: GAP-0394). The process is the owner,
// so it takes back what is its own: this only ever removes access, never
// adds it, and an entry another account owns is left as it is (the audit
// store still refuses it). Symbolic links are never followed or changed.
func ReclaimOwnTree(dir string) error {
	uid := os.Geteuid()
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && !d.Type().IsRegular() {
			return nil
		}
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
		if d.IsDir() {
			flags |= unix.O_DIRECTORY
		}
		fd, err := unix.Open(path, flags, 0)
		if err != nil {
			return fmt.Errorf("audit: reclaim %s: %w", path, err)
		}
		defer unix.Close(fd)
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			return fmt.Errorf("audit: reclaim %s: %w", path, err)
		}
		if int(st.Uid) != uid {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		isDir := st.Mode&unix.S_IFMT == unix.S_IFDIR
		if isDir != d.IsDir() {
			return errors.New("audit: reclaim: " + path + " changed type")
		}
		mode := uint32(st.Mode) & 0o7777
		want := mode &^ (0o077 | unix.S_ISGID)
		if want == mode {
			return nil
		}
		if err := unix.Fchmod(fd, want); err != nil {
			return fmt.Errorf("audit: reclaim %s: %w", path, err)
		}
		return nil
	})
}
