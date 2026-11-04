// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package acquire

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

// CheckRootSocket reports why path is not a socket an unmanaged gateway may
// trust as a root sensor helper, or nil when it is.
//
// An unmanaged gateway names its helper through its environment, so the path
// itself proves nothing. It is trusted only when nobody but root can have put
// a socket there: the socket is root-owned and not writable by others (the
// helper gives the gateway's group write access, which connecting needs), and
// every folder from it to / is a real folder, root-owned and writable by root
// alone. Nothing on the way may be a symbolic link.
func CheckRootSocket(path string) error { return checkRootSocket(path, os.Lstat) }

func checkRootSocket(path string, lstat func(string) (fs.FileInfo, error)) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("helper socket %q is not a clean absolute path", path)
	}
	info, err := lstat(path)
	if err != nil {
		return fmt.Errorf("helper socket %s: %w", path, err)
	}
	if info.Mode().Type() != fs.ModeSocket {
		return fmt.Errorf("helper socket %s is not a socket (%s)", path, info.Mode().Type())
	}
	if uid, ok := ownerUID(info); !ok || uid != 0 {
		return fmt.Errorf("helper socket %s is not owned by root", path)
	}
	if info.Mode().Perm()&0o002 != 0 {
		return fmt.Errorf("helper socket %s is writable by others", path)
	}
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		info, err := lstat(dir)
		if err != nil {
			return fmt.Errorf("helper socket folder %s: %w", dir, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("helper socket folder %s is not a folder", dir)
		}
		if uid, ok := ownerUID(info); !ok || uid != 0 {
			return fmt.Errorf("helper socket folder %s is not owned by root", dir)
		}
		if info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("helper socket folder %s is writable by group or others", dir)
		}
		if dir == "/" {
			return nil
		}
	}
}

// RootSocketAwaitable reports a helper socket that is not there yet in a
// place only root can create it: the socket is absent, and every folder above
// it that exists is a real folder, root-owned and writable by root alone (a
// missing runtime folder is root's to create below such a folder). A gateway
// waits for such a socket and for nothing else (cowork-1-0-8 GAP-0049).
func RootSocketAwaitable(path string) bool { return rootSocketAwaitable(path, os.Lstat) }

func rootSocketAwaitable(path string, lstat func(string) (fs.FileInfo, error)) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	if _, err := lstat(path); !errors.Is(err, fs.ErrNotExist) {
		return false
	}
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		info, err := lstat(dir)
		switch {
		case errors.Is(err, fs.ErrNotExist):
		case err != nil:
			return false
		default:
			if uid, ok := ownerUID(info); !info.IsDir() || !ok || uid != 0 || info.Mode().Perm()&0o022 != 0 {
				return false
			}
		}
		if dir == "/" {
			return true
		}
	}
}

func ownerUID(info fs.FileInfo) (int, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(stat.Uid), true
}

// ErrHelperNotRoot is a helper socket served by a process that is not root.
var ErrHelperNotRoot = errors.New("acquire: the helper socket is not served by root")

// NewRootHelper is NewHelper for a socket that must be served by root: every
// connect checks the kernel-supplied uid of the serving process, so a socket
// another account binds in its place answers nothing.
func NewRootHelper(socketPath string) *Helper {
	helper := NewHelper(socketPath)
	plain := helper.dialer
	helper.dialer = func(ctx context.Context) (net.Conn, error) {
		conn, err := plain(ctx)
		if err != nil {
			return nil, err
		}
		if err := requireRootPeer(conn); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("%w at %s: %w", ErrHelperUnreachable, socketPath, err)
		}
		return conn, nil
	}
	return helper
}

func requireRootPeer(conn net.Conn) error {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return errors.New("acquire: helper connection is not a unix socket")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return err
	}
	uid, credsErr := -1, error(nil)
	if err := raw.Control(func(fd uintptr) { uid, credsErr = peerUIDOf(fd) }); err != nil {
		return err
	}
	if credsErr != nil {
		return credsErr
	}
	if uid != 0 {
		return fmt.Errorf("%w (uid %d)", ErrHelperNotRoot, uid)
	}
	return nil
}

// ProbeRootHelper connects once and reports ErrHelperNotRoot when the socket
// is served by another account. A helper that is not listening yet is not an
// error here: every later connect repeats the check.
func ProbeRootHelper(ctx context.Context, socketPath string) error {
	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(dialCtx, "unix", socketPath)
	if err != nil {
		return nil
	}
	defer conn.Close()
	return requireRootPeer(conn)
}
