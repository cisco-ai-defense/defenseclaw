// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package peercred reads the kernel-verified identity of the process on the
// other end of a connected unix-domain socket.
//
// The kernel records these credentials when the connection is made (for the
// client side: when the server called listen). They come from the peer's
// real process credentials, not from anything the peer sent, which is what
// makes them usable for an authorization decision.
package peercred

import (
	"errors"
	"fmt"
	"net"
	"syscall"
)

// Credentials is the peer process identity.
type Credentials struct {
	UID int
	GID int
	// PID is the peer process id when the platform reports it, else 0.
	PID int
}

// ErrUnsupported reports a platform without peer credentials.
var ErrUnsupported = errors.New("peercred: unix peer credentials are not supported on this platform")

// FromConn returns the peer credentials of a connected unix-domain socket.
func FromConn(conn net.Conn) (Credentials, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return Credentials{}, fmt.Errorf("peercred: %T is not a unix-domain connection", conn)
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return Credentials{}, fmt.Errorf("peercred: raw connection: %w", err)
	}
	return fromRawConn(raw)
}

func fromRawConn(raw syscall.RawConn) (Credentials, error) {
	var (
		credentials Credentials
		readErr     error
	)
	if err := raw.Control(func(fd uintptr) {
		credentials, readErr = fromFD(int(fd))
	}); err != nil {
		return Credentials{}, fmt.Errorf("peercred: control: %w", err)
	}
	if readErr != nil {
		return Credentials{}, readErr
	}
	if credentials.UID < 0 {
		return Credentials{}, errors.New("peercred: kernel returned an invalid uid")
	}
	return credentials, nil
}
