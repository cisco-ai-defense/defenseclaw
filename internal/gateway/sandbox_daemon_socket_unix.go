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

//go:build unix

package gateway

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// BindSandboxDaemonSocket binds the sandbox daemon's CLI socket at path when
// no service manager passed one (macOS, where launchd hands sockets over
// only through cgo). The directory is created 0700 and must be a real
// directory the caller owns; the socket is 0600. A stale socket the caller
// owns is replaced; one a live daemon still answers on is refused.
func BindSandboxDaemonSocket(path string) (net.Listener, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("sandbox daemon: socket path %q is not absolute and clean", path)
	}
	uid := os.Getuid()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("sandbox daemon: socket directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("sandbox daemon: socket directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || statOwner(info) != uid {
		return nil, fmt.Errorf("sandbox daemon: socket directory %s is not a directory of your own", dir)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("sandbox daemon: socket directory: %w", err)
	}
	if existing, err := os.Lstat(path); err == nil {
		if existing.Mode()&os.ModeSocket == 0 || statOwner(existing) != uid {
			return nil, fmt.Errorf("sandbox daemon: %s exists and is not this account's socket", path)
		}
		if conn, err := net.DialTimeout("unix", path, time.Second); err == nil {
			_ = conn.Close()
			return nil, errors.New("sandbox daemon: another sandbox daemon of this account is running")
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("sandbox daemon: remove the stale socket: %w", err)
		}
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("sandbox daemon: listen %s: %w", path, err)
	}
	// The 0700 directory already keeps everyone else out until the chmod.
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("sandbox daemon: socket mode: %w", err)
	}
	return ln, nil
}

func statOwner(info os.FileInfo) int {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid)
	}
	return -1
}
