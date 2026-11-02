// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"syscall"
)

// reservedLoopbackSocket is a TCP socket for refusingAPIAddr; Windows
// sockets are not inherited unless a process asks for it.
func reservedLoopbackSocket() (syscall.Handle, error) {
	return syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
}

func closeReservedSocket(socket syscall.Handle) error { return syscall.Closesocket(socket) }

// isWindowsConnectionRefused reports WSAECONNREFUSED.
func isWindowsConnectionRefused(err error) bool { return errors.Is(err, syscall.Errno(10061)) }
