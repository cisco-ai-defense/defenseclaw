//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// enokey has no macOS equivalent.
const enokey = syscall.Errno(0)

// ecryptfsSupported: macOS has no ecryptfs private homes, so its lock
// markers are ordinary user files there.
const ecryptfsSupported = false

// platformMountAt reads the kernel mount table (getfsstat with MNT_NOWAIT,
// which never asks a filesystem for fresh statistics), so a hung or hostile
// mount cannot block or answer it. f_owner is the uid that mounted it.
func platformMountAt(path string) (unixMount, bool, error) {
	path = filepath.Clean(path)
	// /Users lives on the data volume; the table may name either path.
	aliases := map[string]bool{path: true, filepath.Join("/System/Volumes/Data", path): true}
	for attempt := 0; attempt < 3; attempt++ {
		n, err := unix.Getfsstat(nil, unix.MNT_NOWAIT)
		if err != nil {
			return unixMount{}, false, err
		}
		buf := make([]unix.Statfs_t, n+8)
		n, err = unix.Getfsstat(buf, unix.MNT_NOWAIT)
		if err != nil {
			return unixMount{}, false, err
		}
		if n >= len(buf) {
			continue // the table grew between the two calls
		}
		var found unixMount
		ok := false
		for _, entry := range buf[:n] {
			if !aliases[filepath.Clean(unix.ByteSliceToString(entry.Mntonname[:]))] {
				continue
			}
			found = unixMount{FSType: unix.ByteSliceToString(entry.Fstypename[:]), Owner: int(entry.Owner)}
			ok = true
		}
		return found, ok, nil
	}
	return unixMount{}, false, syscall.EAGAIN
}

// platformLiveSession is used only for ecryptfs homes, which macOS lacks.
func platformLiveSession(int) bool { return false }
