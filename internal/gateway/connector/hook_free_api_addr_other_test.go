// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import "syscall"

// reservedLoopbackSocket is a TCP socket for refusingAPIAddr that the hook
// programs a test starts do not inherit.
func reservedLoopbackSocket() (int, error) {
	socket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		return 0, err
	}
	syscall.CloseOnExec(socket)
	return socket, nil
}

func closeReservedSocket(socket int) error { return syscall.Close(socket) }

func isWindowsConnectionRefused(error) bool { return false }
