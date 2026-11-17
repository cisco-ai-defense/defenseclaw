//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package peercred

import (
	"errors"
	"fmt"
	"math/bits"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	tcpTableOwnerPIDAll = 5
	mibTCPStateEstab    = 5
	maxTCPTableBytes    = 16 << 20
)

var getExtendedTCPTableProc = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")

// mibTCPRowOwnerPID is MIB_TCPROW_OWNER_PID.
type mibTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

// mibTCP6RowOwnerPID is MIB_TCP6ROW_OWNER_PID.
type mibTCP6RowOwnerPID struct {
	LocalAddr     [16]byte
	LocalScopeID  uint32
	LocalPort     uint32
	RemoteAddr    [16]byte
	RemoteScopeID uint32
	RemotePort    uint32
	State         uint32
	OwningPID     uint32
}

// loopbackTCPOwnerPID is replaceable in tests.
var loopbackTCPOwnerPID = tcpClientOwnerPID

// processAccountSID is replaceable in tests.
var processAccountSID = tokenUserSID

// LoopbackTCPPeerAccount returns the SID of the account whose process owns
// the client end of a loopback TCP connection this process accepted. The
// owner PID comes from the kernel connection table, and the account from
// that process's token, so the answer is what Windows recorded, not what
// the client sent. The table is read again after the token, so a process
// that exited and whose PID was reused in between is not named.
func LoopbackTCPPeerAccount(local, remote *net.TCPAddr) (string, error) {
	if local == nil || remote == nil || !local.IP.IsLoopback() || !remote.IP.IsLoopback() {
		return "", errors.New("peercred: the connection is not on a loopback address")
	}
	pid, err := loopbackTCPOwnerPID(local, remote)
	if err != nil {
		return "", err
	}
	sid, err := processAccountSID(pid)
	if err != nil {
		return "", err
	}
	again, err := loopbackTCPOwnerPID(local, remote)
	if err != nil {
		return "", err
	}
	if again != pid {
		return "", fmt.Errorf("peercred: the connection owner changed from PID %d to %d", pid, again)
	}
	return sid, nil
}

// tcpClientOwnerPID finds the ESTABLISHED row whose local end is the
// client's address and whose remote end is the address the server accepted
// on, and returns its owner PID.
func tcpClientOwnerPID(local, remote *net.TCPAddr) (uint32, error) {
	if v4 := remote.IP.To4(); v4 != nil {
		server := local.IP.To4()
		if server == nil {
			return 0, ErrPeerNotFound
		}
		rows, err := readOwnerPIDTable[mibTCPRowOwnerPID](windows.AF_INET)
		if err != nil {
			return 0, err
		}
		for _, row := range rows {
			if row.State != mibTCPStateEstab {
				continue
			}
			if ipv4FromMIB(row.LocalAddr) == [4]byte(v4) && mibPort(row.LocalPort) == remote.Port &&
				ipv4FromMIB(row.RemoteAddr) == [4]byte(server) && mibPort(row.RemotePort) == local.Port {
				if row.OwningPID == 0 {
					return 0, ErrPeerNotFound
				}
				return row.OwningPID, nil
			}
		}
		return 0, ErrPeerNotFound
	}
	client, server := remote.IP.To16(), local.IP.To16()
	if client == nil || server == nil {
		return 0, ErrPeerNotFound
	}
	rows, err := readOwnerPIDTable[mibTCP6RowOwnerPID](windows.AF_INET6)
	if err != nil {
		return 0, err
	}
	for _, row := range rows {
		if row.State != mibTCPStateEstab {
			continue
		}
		if row.LocalAddr == [16]byte(client) && mibPort(row.LocalPort) == remote.Port &&
			row.RemoteAddr == [16]byte(server) && mibPort(row.RemotePort) == local.Port {
			if row.OwningPID == 0 {
				return 0, ErrPeerNotFound
			}
			return row.OwningPID, nil
		}
	}
	return 0, ErrPeerNotFound
}

func mibPort(value uint32) int { return int(bits.ReverseBytes16(uint16(value))) }

func ipv4FromMIB(value uint32) [4]byte {
	return [4]byte{byte(value), byte(value >> 8), byte(value >> 16), byte(value >> 24)}
}

// tokenUserSID reads the account SID of a process's primary token. Every
// handle is closed on every path.
func tokenUserSID(pid uint32) (string, error) {
	if pid == 0 {
		return "", ErrPeerNotFound
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", fmt.Errorf("peercred: open process %d: %w", pid, err)
	}
	defer windows.CloseHandle(process) //nolint:errcheck // best-effort close of a query handle
	var token windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		return "", fmt.Errorf("peercred: open token of process %d: %w", pid, err)
	}
	defer token.Close() //nolint:errcheck // best-effort close of a query handle
	user, err := token.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("peercred: read token user of process %d: %w", pid, err)
	}
	if user == nil || user.User.Sid == nil {
		return "", fmt.Errorf("peercred: process %d has no token user", pid)
	}
	return user.User.Sid.String(), nil
}

func readOwnerPIDTable[Row mibTCPRowOwnerPID | mibTCP6RowOwnerPID](family uint32) ([]Row, error) {
	var size uint32
	err := callGetExtendedTCPTable(nil, &size, family)
	if err != nil && !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
		return nil, fmt.Errorf("peercred: size owner-PID table: %w", err)
	}
	for attempts := 0; attempts < 3; attempts++ {
		if size < 4 || size > maxTCPTableBytes {
			return nil, fmt.Errorf("peercred: owner-PID table size %d is invalid", size)
		}
		buffer := make([]byte, size)
		err = callGetExtendedTCPTable(buffer, &size, family)
		if errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("peercred: read owner-PID table: %w", err)
		}
		count := *(*uint32)(unsafe.Pointer(&buffer[0]))
		var zero Row
		required := uint64(4) + uint64(count)*uint64(unsafe.Sizeof(zero))
		if required > uint64(len(buffer)) {
			return nil, errors.New("peercred: owner-PID table is truncated")
		}
		rows := make([]Row, int(count))
		if count > 0 {
			copy(rows, unsafe.Slice((*Row)(unsafe.Pointer(&buffer[4])), int(count)))
		}
		return rows, nil
	}
	return nil, errors.New("peercred: owner-PID table changed during a bounded read")
}

func callGetExtendedTCPTable(buffer []byte, size *uint32, family uint32) error {
	// LazyProc.Call panics when the export cannot be resolved; Find turns
	// that into an error.
	if err := getExtendedTCPTableProc.Find(); err != nil {
		return fmt.Errorf("peercred: resolve GetExtendedTcpTable: %w", err)
	}
	var pointer uintptr
	if len(buffer) > 0 {
		pointer = uintptr(unsafe.Pointer(&buffer[0]))
	}
	result, _, _ := getExtendedTCPTableProc.Call(pointer, uintptr(unsafe.Pointer(size)), 0,
		uintptr(family), uintptr(tcpTableOwnerPIDAll), 0)
	if result != 0 {
		return syscall.Errno(result)
	}
	return nil
}
