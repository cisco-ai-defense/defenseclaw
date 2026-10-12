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

package tetragon

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// trustPolicy is who must own Tetragon's files and serve its socket: root.
// Tests substitute their own uid, because they cannot create root-owned
// fixtures.
type trustPolicy struct {
	ownerUID int
	peerUID  int
}

var rootTrust = trustPolicy{ownerUID: 0, peerUID: 0}

// supported reports whether this platform can reach Tetragon at all.
func supported() bool { return true }

// resolveIn resolves the directory part of path (the stock /var/run is a
// link to /run) and returns the directory and the final name, which is never
// followed.
func resolveIn(path string) (string, string, error) {
	dir, err := filepath.EvalSymlinks(filepath.Dir(filepath.Clean(path)))
	if err != nil {
		return "", "", err
	}
	return dir, filepath.Base(path), nil
}

func ownerOf(info fs.FileInfo) (int, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(stat.Uid), true
}

// checkInfoFile: the discovery file names the socket the helper will trust,
// so it must be root's: a regular file, root-owned, not group- or
// world-writable.
func (t trustPolicy) checkInfoFile(path string) error {
	dir, name, err := resolveIn(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return refuse(ReasonUnavailable, err, "no %s", path)
		}
		return refuse(ReasonUnavailable, err, "resolve %s: %v", path, err)
	}
	// A writable discovery directory lets another account replace the
	// root-owned file between validation and open. Resolve the stock /var/run
	// link first, then require its actual directory to be root's and private
	// to root for writes.
	dirInfo, err := os.Stat(dir)
	if err != nil {
		return refuse(ReasonUnavailable, err, "stat %s: %v", dir, err)
	}
	if uid, ok := ownerOf(dirInfo); !ok || uid != t.ownerUID {
		return refuse(ReasonUntrusted, nil, "the info directory %s is owned by uid %d, not %d", dir, uid, t.ownerUID)
	}
	if dirInfo.Mode().Perm()&0o022 != 0 {
		return refuse(ReasonUntrusted, nil, "the info directory %s is group- or world-writable", dir)
	}
	info, err := os.Lstat(filepath.Join(dir, name))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return refuse(ReasonUnavailable, err, "no %s", path)
		}
		return refuse(ReasonUnavailable, err, "stat %s: %v", path, err)
	}
	if !info.Mode().IsRegular() {
		return refuse(ReasonUntrusted, nil, "%s is not a regular file", path)
	}
	if uid, ok := ownerOf(info); !ok || uid != t.ownerUID {
		return refuse(ReasonUntrusted, nil, "%s is owned by uid %d, not %d", path, uid, t.ownerUID)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return refuse(ReasonUntrusted, nil, "%s is group- or world-writable (%v)", path, info.Mode().Perm())
	}
	return nil
}

// checkSocket: the socket and its directory must be root-owned and not
// world-writable (the stock root:root 0660 socket passes).
func (t trustPolicy) checkSocket(path string) error {
	dir, name, err := resolveIn(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return refuse(ReasonUnavailable, err, "no %s", path)
		}
		return refuse(ReasonUnavailable, err, "resolve %s: %v", path, err)
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		return refuse(ReasonUnavailable, err, "stat %s: %v", dir, err)
	}
	if uid, ok := ownerOf(dirInfo); !ok || uid != t.ownerUID {
		return refuse(ReasonUntrusted, nil, "the socket directory %s is owned by uid %d, not %d", dir, uid, t.ownerUID)
	}
	if dirInfo.Mode().Perm()&0o002 != 0 {
		return refuse(ReasonUntrusted, nil, "the socket directory %s is world-writable", dir)
	}
	info, err := os.Lstat(filepath.Join(dir, name))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return refuse(ReasonUnavailable, err, "no socket at %s", path)
		}
		return refuse(ReasonUnavailable, err, "stat %s: %v", path, err)
	}
	if info.Mode().Type() != fs.ModeSocket {
		return refuse(ReasonUntrusted, nil, "%s is not a socket", path)
	}
	if uid, ok := ownerOf(info); !ok || uid != t.ownerUID {
		return refuse(ReasonUntrusted, nil, "the socket %s is owned by uid %d, not %d", path, uid, t.ownerUID)
	}
	if info.Mode().Perm()&0o002 != 0 {
		return refuse(ReasonUntrusted, nil, "the socket %s is world-writable", path)
	}
	return nil
}

// checkPeer: the process serving the socket must be uid 0 and the Tetragon
// pid the info file names. SO_PEERCRED is filled in by the kernel at connect
// time and cannot be forged by the server.
func (t trustPolicy) checkPeer(conn net.Conn, pid int) error {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return refuse(ReasonUntrusted, nil, "the connection is %T, which carries no credentials", conn)
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return refuse(ReasonUntrusted, err, "peer credentials unavailable: %v", err)
	}
	var (
		cred    *unix.Ucred
		credErr error
	)
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return refuse(ReasonUntrusted, err, "peer credentials unavailable: %v", err)
	}
	if credErr != nil || cred == nil {
		return refuse(ReasonUntrusted, credErr, "peer credentials unavailable: %v", credErr)
	}
	if int(cred.Uid) != t.peerUID {
		return refuse(ReasonUntrusted, nil, "the socket is served by uid %d, not %d", cred.Uid, t.peerUID)
	}
	if int(cred.Pid) != pid {
		return refuse(ReasonUntrusted, nil, "the socket is served by pid %d, not the Tetragon pid %d", cred.Pid, pid)
	}
	return nil
}

// listenerOwnedBy reports whether the TCP listener on port belongs to pid:
// its socket inode is one of the pid's descriptors. Tetragon's metrics are
// read only then, so another local process listening on the port cannot
// feed the helper numbers.
func listenerOwnedBy(port int, pid int) error {
	inodes := map[string]bool{}
	for _, table := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		file, err := os.Open(table)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			// sl local_address rem_address st ... inode (field 9)
			if len(fields) < 10 || fields[3] != "0A" {
				continue
			}
			_, hexPort, ok := strings.Cut(fields[1], ":")
			if !ok {
				continue
			}
			if value, err := strconv.ParseInt(hexPort, 16, 32); err == nil && int(value) == port {
				inodes[fields[9]] = true
			}
		}
		_ = file.Close()
	}
	if len(inodes) == 0 {
		return fmt.Errorf("nothing listens on port %d", port)
	}
	dir := filepath.Join("/proc", strconv.Itoa(pid), "fd")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read %s: %w", dir, err)
	}
	for _, entry := range entries {
		link, err := os.Readlink(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		if inode, ok := strings.CutPrefix(link, "socket:["); ok && inodes[strings.TrimSuffix(inode, "]")] {
			return nil
		}
	}
	return fmt.Errorf("the listener on port %d is not Tetragon's (pid %d)", port, pid)
}
