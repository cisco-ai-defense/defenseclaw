// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package ipc

import (
	"fmt"
	"net"
)

// peerIdentity carries the credentials extracted from a UDS peer.
// PID may be zero on Linux (unavailable when the caller does not
// share the pid namespace) — treat PID as informational only.
type peerIdentity struct {
	PID int32
	UID uint32
	GID uint32
}

// extractPeerIdentity reads the peer credentials from a UDS
// net.Conn. Returns an error on non-UDS connections or when the
// kernel refuses the getsockopt call (which happens only for
// sockets whose peer has disconnected between accept and this call).
func extractPeerIdentity(c net.Conn) (peerIdentity, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return peerIdentity{}, fmt.Errorf("ipc: peer identity: expected *net.UnixConn, got %T", c)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return peerIdentity{}, fmt.Errorf("ipc: peer identity: syscall conn: %w", err)
	}
	var (
		id     peerIdentity
		optErr error
	)
	ctrlErr := raw.Control(func(fd uintptr) {
		optErr = readPeerIdentity(int(fd), &id)
	})
	if ctrlErr != nil {
		return peerIdentity{}, fmt.Errorf("ipc: peer identity: control: %w", ctrlErr)
	}
	if optErr != nil {
		return peerIdentity{}, optErr
	}
	return id, nil
}

// validatingListener wraps a UDS net.Listener and enforces a UID
// allowlist at accept time. Rejected connections are closed and
// silently skipped so the gRPC server never sees them.
type validatingListener struct {
	inner       net.Listener
	allowedUIDs map[uint32]struct{}
	logRejectFn func(peerIdentity, string)
}

func newValidatingListener(inner net.Listener, allowedUIDs []int, logReject func(peerIdentity, string)) net.Listener {
	if len(allowedUIDs) == 0 {
		return inner
	}
	set := make(map[uint32]struct{}, len(allowedUIDs))
	for _, u := range allowedUIDs {
		if u < 0 {
			continue
		}
		set[uint32(u)] = struct{}{}
	}
	return &validatingListener{inner: inner, allowedUIDs: set, logRejectFn: logReject}
}

func (l *validatingListener) Accept() (net.Conn, error) {
	for {
		c, err := l.inner.Accept()
		if err != nil {
			return nil, err
		}
		id, extractErr := extractPeerIdentity(c)
		if extractErr != nil {
			if l.logRejectFn != nil {
				l.logRejectFn(peerIdentity{}, extractErr.Error())
			}
			_ = c.Close()
			continue
		}
		if _, ok := l.allowedUIDs[id.UID]; !ok {
			if l.logRejectFn != nil {
				l.logRejectFn(id, "uid not in allow list")
			}
			_ = c.Close()
			continue
		}
		return c, nil
	}
}

func (l *validatingListener) Close() error   { return l.inner.Close() }
func (l *validatingListener) Addr() net.Addr { return l.inner.Addr() }

// readPeerIdentity is the platform-specific getsockopt(2) call for
// peer credentials. Implemented in peerauth_linux.go and
// peerauth_darwin.go via init(), so callers can rely on it being
// non-nil under the linux || darwin build tag.
var readPeerIdentity func(fd int, id *peerIdentity) error
