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

package daemon

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// daemonLaunchPin binds the daemon child's launch to the gateway file this
// process checked (#643). On Linux the child starts from /proc/self/exe, the
// file already running, and the pin adds nothing. macOS has no descriptor
// exec, so the pin holds the resolved file open, requires that only root or
// this account can change it or any directory above it, and records their
// identity and change times. They must be unchanged once the child exists, or
// the child is stopped and the start fails.
type daemonLaunchPin struct {
	path     string
	file     *os.File
	snapshot []launchPathEntry
}

type launchPathEntry struct {
	path         string
	dev, ino     uint64
	mode         uint32
	uid, gid     uint32
	mtime, ctime unix.Timespec
}

// darwinAdminGID is the macOS admin group. Directories such as /Applications
// are writable by it; its members are administrators, who can change any path.
const darwinAdminGID = 80

// launchPathTrusted checks who can change the pinned path. Tests replace it,
// since their temporary directories sit below world-writable ones.
var launchPathTrusted = trustedLaunchPath

func pinDaemonLaunch(executable string) (*daemonLaunchPin, error) {
	if path := daemonExecPath(executable); path != executable {
		return &daemonLaunchPin{path: path}, nil
	}
	return pinLaunchPath(executable)
}

func pinLaunchPath(executable string) (*daemonLaunchPin, error) {
	resolved, err := filepath.EvalSymlinks(executable)
	if err == nil {
		resolved, err = filepath.Abs(resolved)
	}
	if err != nil {
		return nil, fmt.Errorf("daemon: resolve gateway executable: %w", err)
	}
	file, err := os.OpenFile(resolved, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("daemon: open gateway executable: %w", err)
	}
	pin := &daemonLaunchPin{path: resolved, file: file}
	snapshot, err := pin.current()
	if err == nil {
		err = launchPathTrusted(snapshot)
	}
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("daemon: refusing to start the gateway from %s: %w", resolved, err)
	}
	pin.snapshot = snapshot
	return pin, nil
}

// current fails unless the path still names the held file and returns the
// path's snapshot.
func (p *daemonLaunchPin) current() ([]launchPathEntry, error) {
	held, err := p.file.Stat()
	if err != nil {
		return nil, err
	}
	named, err := os.Lstat(p.path)
	if err != nil {
		return nil, err
	}
	if !os.SameFile(held, named) {
		return nil, errors.New("the path no longer names the checked file")
	}
	return launchPathSnapshot(p.path)
}

// check fails if the pinned path or a directory above it changed since the
// pin was taken.
func (p *daemonLaunchPin) check() error {
	if p == nil || p.file == nil {
		return nil
	}
	now, err := p.current()
	if err != nil || !slices.Equal(now, p.snapshot) {
		return fmt.Errorf("daemon: the gateway executable %s changed while the gateway started; run the command again", p.path)
	}
	return nil
}

func (p *daemonLaunchPin) close() {
	if p != nil && p.file != nil {
		_ = p.file.Close()
	}
}

// launchPathSnapshot records path and every directory above it.
func launchPathSnapshot(path string) ([]launchPathEntry, error) {
	var entries []launchPathEntry
	for current := path; ; current = filepath.Dir(current) {
		var st unix.Stat_t
		if err := unix.Lstat(current, &st); err != nil {
			return nil, fmt.Errorf("inspect %s: %w", current, err)
		}
		entries = append(entries, launchPathEntry{
			path:  current,
			dev:   uint64(st.Dev), //nolint:unconvert // int32 on darwin
			ino:   st.Ino,
			mode:  uint32(st.Mode), //nolint:unconvert // uint16 on darwin
			uid:   st.Uid,
			gid:   st.Gid,
			mtime: st.Mtim,
			ctime: st.Ctim,
		})
		if filepath.Dir(current) == current {
			return entries, nil
		}
	}
}

// trustedLaunchPath admits an executable regular file whose every path
// element is owned by root or this account and writable by nobody else
// (on macOS the admin group may also write a directory).
func trustedLaunchPath(entries []launchPathEntry) error {
	euid := uint32(os.Geteuid())
	for i, entry := range entries {
		kind := entry.mode & unix.S_IFMT
		if (i == 0 && kind != unix.S_IFREG) || (i > 0 && kind != unix.S_IFDIR) {
			return fmt.Errorf("%s: not a regular file or directory", entry.path)
		}
		if entry.uid != 0 && entry.uid != euid {
			return fmt.Errorf("%s: owned by uid %d, not root or this account", entry.path, entry.uid)
		}
		writable := entry.mode & 0o022
		if i > 0 && runtime.GOOS == "darwin" && entry.gid == darwinAdminGID {
			writable &^= 0o020
		}
		if writable != 0 {
			return fmt.Errorf("%s: other accounts can write it (mode %04o)", entry.path, entry.mode&0o7777)
		}
		if err := managed.ValidatePathACL(entry.path); err != nil {
			return err
		}
	}
	if entries[0].mode&0o111 == 0 {
		return fmt.Errorf("%s: not executable", entries[0].path)
	}
	return nil
}
