// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package plane

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// localImageFS reports a file on a local file system. Images on network and
// FUSE file systems, whose contents and attributes the account or a remote
// controls and whose reads may never return, are not hashed.
func localImageFS(file *os.File) bool {
	var stat unix.Statfs_t
	if unix.Fstatfs(int(file.Fd()), &stat) != nil {
		return false
	}
	name := string(bytes.TrimRight(stat.Fstypename[:], "\x00"))
	switch {
	case name == "nfs", name == "smbfs", name == "afpfs", name == "webdav", name == "cifs",
		strings.Contains(name, "fuse"):
		return false
	}
	return true
}

// statImageKey is the identity of an open image file.
func statImageKey(file *os.File) (imageKey, bool) {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return imageKey{}, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return imageKey{}, false
	}
	return imageKey{
		device: uint64(uint32(stat.Dev)), file: stat.Ino, size: stat.Size,
		changed: stat.Ctimespec.Nano(), written: stat.Mtimespec.Nano(),
	}, true
}

// darwinClientImage pins the exec target Endpoint Security named, bound to
// the file ES saw at exec time: the file now at that path must have the
// device, inode, size and change time of the exec-time stat, so a file
// renamed or written over the install path after the exec is not read as the
// image that ran. The process need not be alive. Only the open runs here, on
// the ES reader; the digest is the cached one, or "" while clientImages
// hashes the file.
func darwinClientImage(target esFile, account string) (sum, version string) {
	if target.PathTruncated {
		return "", ""
	}
	path := target.Path
	if version = claudeImageVersion(path); version == "" && filepath.Base(path) == "claude" {
		// A launcher link; the stat below is still the exec-time vnode's.
		if resolved, err := filepath.EvalSymlinks(path); err == nil {
			path, version = resolved, claudeImageVersion(resolved)
		}
	}
	if version == "" {
		return "", ""
	}
	changed, err := time.Parse(time.RFC3339Nano, target.Stat.Changed)
	if err != nil {
		return "", version
	}
	file, err := openNoFollow(path)
	if err != nil {
		return "", version
	}
	key, ok := statImageKey(file)
	if !ok || key.device != uint64(uint32(target.Stat.Dev)) || key.file != target.Stat.Ino ||
		key.size != target.Stat.Size || key.changed != changed.UnixNano() {
		file.Close()
		return "", version
	}
	sum, _ = clientImages.digestOf(file, key, account, nil)
	return sum, version
}
