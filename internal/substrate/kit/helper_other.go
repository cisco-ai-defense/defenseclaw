// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package kit

import (
	"errors"
	"net"
	"os"
	"syscall"
	"time"
)

// Actors are Linux. Elsewhere the helper uses only its socket file and does
// not check its peer; the package builds for tooling and tests.

var errHelperRunning = errors.New("actor hook helper already running")

func listenHelper(path string) ([]net.Listener, error) {
	if c, err := net.DialTimeout("unix", path, 100*time.Millisecond); err == nil {
		c.Close()
		return nil, errHelperRunning
	}
	_ = os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	return []net.Listener{l}, nil
}

func dialHelper(path string) (net.Conn, error) {
	return net.DialTimeout("unix", path, 200*time.Millisecond)
}

func peerIsSameUser(net.Conn) bool   { return true }
func peerIsThisBinary(net.Conn) bool { return true }

func detachedAttr() *syscall.SysProcAttr { return nil }
