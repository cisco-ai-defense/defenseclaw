// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package kit

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// abstractName is the helper's abstract socket (Linux only).
func abstractName() string { return fmt.Sprintf("@defenseclaw-actor-hook-%d", os.Getuid()) }

func listenHelper(path string) ([]net.Listener, error) {
	var out []net.Listener
	abs, err := net.Listen("unix", abstractName())
	if err != nil {
		return nil, errHelperRunning
	}
	out = append(out, abs)
	// The file socket is a second door; a stale file from a dead helper is
	// replaced (the abstract socket above proves no helper runs).
	_ = os.Remove(path)
	if l, err := net.Listen("unix", path); err == nil {
		out = append(out, l)
	}
	return out, nil
}

var errHelperRunning = errors.New("actor hook helper already running")

func dialHelper(path string) (net.Conn, error) {
	d := net.Dialer{Timeout: 200 * time.Millisecond}
	if c, err := d.Dial("unix", path); err == nil {
		return c, nil
	}
	return d.Dial("unix", abstractName())
}

func peerCred(conn net.Conn) (*unix.Ucred, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, errors.New("not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return nil, err
	}
	var cred *unix.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return nil, err
	}
	return cred, cerr
}

func peerIsSameUser(conn net.Conn) bool {
	cred, err := peerCred(conn)
	return err == nil && int(cred.Uid) == os.Getuid()
}

// peerIsThisBinary checks that the helper is this user's process running the
// helper program (helperPath), so a process the agent started cannot stand
// in for the helper and answer every hook itself.
func peerIsThisBinary(conn net.Conn) bool {
	cred, err := peerCred(conn)
	if err != nil || int(cred.Uid) != os.Getuid() {
		return false
	}
	peerExe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", cred.Pid))
	if err != nil {
		return false
	}
	self, err := helperPath()
	if err != nil {
		return false
	}
	selfResolved, err := filepath.EvalSymlinks(self)
	if err != nil {
		return false
	}
	return filepath.Clean(peerExe) == selfResolved
}

func detachedAttr() *syscall.SysProcAttr { return &syscall.SysProcAttr{Setsid: true} }
