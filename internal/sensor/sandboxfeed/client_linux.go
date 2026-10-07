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

package sandboxfeed

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// checkSocket refuses a feed socket, or a directory holding it, that is not
// the trusted owner's or that anyone may write: whoever could replace either
// could serve a gateway a made-up process tree.
func checkSocket(path string, trust trustPolicy) error {
	dir := filepath.Dir(path)
	for _, check := range []struct {
		path string
		dir  bool
	}{{dir, true}, {path, false}} {
		info, err := os.Lstat(check.path)
		switch {
		case errors.Is(err, os.ErrNotExist):
			return fmt.Errorf("%w: %s", ErrNotInstalled, check.path)
		case errors.Is(err, os.ErrPermission):
			return fmt.Errorf("%w: %v (the feed is for members of the %s group)", ErrNotPermitted, err, DockerGroup)
		case err != nil:
			return err
		}
		switch {
		case check.dir && !info.IsDir():
			return fmt.Errorf("%w: %s is not a directory", ErrUntrusted, check.path)
		case !check.dir && info.Mode()&os.ModeSocket == 0:
			return fmt.Errorf("%w: %s is not a socket", ErrUntrusted, check.path)
		case info.Mode().Perm()&0o002 != 0:
			return fmt.Errorf("%w: %s is writable by every account", ErrUntrusted, check.path)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || int(stat.Uid) != trust.uid {
			return fmt.Errorf("%w: %s is not owned by uid %d", ErrUntrusted, check.path, trust.uid)
		}
	}
	return nil
}

// checkServer refuses a connection whose server is not the trusted uid.
func checkServer(conn net.Conn, trust trustPolicy) error {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("%w: not a unix socket", ErrUntrusted)
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return err
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return err
	}
	if credErr != nil {
		return fmt.Errorf("%w: SO_PEERCRED: %v", ErrUntrusted, credErr)
	}
	if int(cred.Uid) != trust.uid {
		return fmt.Errorf("%w: the feed socket is served by uid %d", ErrUntrusted, cred.Uid)
	}
	return nil
}
