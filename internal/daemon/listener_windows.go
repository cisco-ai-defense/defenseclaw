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

//go:build windows

package daemon

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	tcpTableOwnerPIDListener = 3
	errorInsufficientBuffer  = windows.Errno(122)
)

var getExtendedTCPTable = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")

var callExtendedTCPTable = func(table unsafe.Pointer, size *uint32, family uint32) windows.Errno {
	result, _, _ := getExtendedTCPTable.Call(
		uintptr(table), uintptr(unsafe.Pointer(size)), 0, uintptr(family), tcpTableOwnerPIDListener, 0,
	)
	return windows.Errno(result)
}

type tcp4OwnerPIDRow struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	PID        uint32
}

type tcp6OwnerPIDRow struct {
	LocalAddr   [16]byte
	LocalScope  uint32
	LocalPort   uint32
	RemoteAddr  [16]byte
	RemoteScope uint32
	RemotePort  uint32
	State       uint32
	PID         uint32
}

func listenerOwnerPID(host string, port int) (int, error) {
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("%w: invalid port %d", ErrListenerInspectionUnavailable, port)
	}
	owners := make(map[int]struct{})
	if err := collectTCP4Owners(port, host, owners); err != nil {
		return 0, err
	}
	if err := collectTCP6Owners(port, host, owners); err != nil {
		return 0, err
	}
	if len(owners) == 0 {
		return 0, ErrNoListener
	}
	if len(owners) != 1 {
		return 0, fmt.Errorf("listener ownership is ambiguous on %s:%d", host, port)
	}
	for pid := range owners {
		return pid, nil
	}
	return 0, ErrNoListener
}

func listenerAddressMatches(host string, actual net.IP) bool {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	switch strings.ToLower(host) {
	case "", "*":
		return true
	case "localhost":
		return actual.IsLoopback() || actual.IsUnspecified()
	}
	wanted := net.ParseIP(host)
	if wanted == nil {
		// Non-IP bind names require DNS resolution inside net.Listen. Treat
		// their port conservatively rather than guessing a different address.
		return true
	}
	if wanted.IsUnspecified() {
		if wanted.To4() != nil {
			return actual.To4() != nil
		}
		// An IPv6 wildcard listener may accept IPv4-mapped connections on
		// Windows, so both families can collide.
		return true
	}
	if wanted.To4() != nil && actual.To4() == nil {
		return false
	}
	if wanted.To4() == nil && actual.To4() != nil {
		return false
	}
	return actual.IsUnspecified() || wanted.Equal(actual)
}

func collectTCP4Owners(port int, host string, owners map[int]struct{}) error {
	return walkExtendedTCPTable(windows.AF_INET, unsafe.Sizeof(tcp4OwnerPIDRow{}), func(row unsafe.Pointer) {
		r := (*tcp4OwnerPIDRow)(row)
		if int(windows.Ntohs(uint16(r.LocalPort))) != port {
			return
		}
		addrBytes := *(*[4]byte)(unsafe.Pointer(&r.LocalAddr))
		if listenerAddressMatches(host, net.IP(addrBytes[:])) {
			owners[int(r.PID)] = struct{}{}
		}
	})
}

func collectTCP6Owners(port int, host string, owners map[int]struct{}) error {
	return walkExtendedTCPTable(windows.AF_INET6, unsafe.Sizeof(tcp6OwnerPIDRow{}), func(row unsafe.Pointer) {
		r := (*tcp6OwnerPIDRow)(row)
		if int(windows.Ntohs(uint16(r.LocalPort))) != port {
			return
		}
		if listenerAddressMatches(host, net.IP(r.LocalAddr[:])) {
			owners[int(r.PID)] = struct{}{}
		}
	})
}

func walkExtendedTCPTable(family uint32, rowSize uintptr, visit func(unsafe.Pointer)) error {
	var size uint32
	result := callExtendedTCPTable(nil, &size, family)
	if result != errorInsufficientBuffer && result != 0 {
		return listenerTableError(result)
	}
	for range 4 {
		if size == 0 {
			return nil
		}
		buffer := make([]byte, size)
		result = callExtendedTCPTable(unsafe.Pointer(&buffer[0]), &size, family)
		if result == errorInsufficientBuffer {
			continue
		}
		if result != 0 {
			return listenerTableError(result)
		}
		count := *(*uint32)(unsafe.Pointer(&buffer[0]))
		offset := uintptr(unsafe.Sizeof(count))
		for i := uint32(0); i < count; i++ {
			row := unsafe.Pointer(uintptr(unsafe.Pointer(&buffer[0])) + offset + uintptr(i)*rowSize)
			visit(row)
		}
		return nil
	}
	return listenerTableError(errorInsufficientBuffer)
}

func listenerTableError(err windows.Errno) error {
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return fmt.Errorf("listener ownership access denied: %w", err)
	}
	return fmt.Errorf("%w: %v", ErrListenerInspectionUnavailable, err)
}
