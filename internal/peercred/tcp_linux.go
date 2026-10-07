//go:build linux

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
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
)

// procNetTCPTables are the TCP tables of this process's network namespace.
// /proc/self/net stays readable when the service runs with ProcSubset=pid,
// which hides /proc/net.
var procNetTCPTables = []string{"/proc/self/net/tcp", "/proc/self/net/tcp6"}

func loopbackTCPOwner(local, remote *net.TCPAddr) (int, error) {
	for _, path := range procNetTCPTables {
		file, err := os.Open(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return -1, fmt.Errorf("peercred: read %s: %w", path, err)
		}
		uid, found, err := tcpTableOwner(file, local, remote)
		_ = file.Close()
		if err != nil {
			return -1, fmt.Errorf("peercred: read %s: %w", path, err)
		}
		if found {
			return uid, nil
		}
	}
	return -1, ErrPeerNotFound
}

// tcpTableOwner finds the client's socket in one /proc/net/tcp{,6} table: its
// local end is the client's address and its remote end the address the
// connection was accepted on. A TIME_WAIT row carries no owner and is skipped.
func tcpTableOwner(table io.Reader, local, remote *net.TCPAddr) (int, bool, error) {
	scanner := bufio.NewScanner(table)
	scanner.Buffer(make([]byte, 0, 4096), 64<<10)
	header := true
	for scanner.Scan() {
		if header {
			header = false
			continue
		}
		// sl local_address rem_address st tx:rx tr:when retrnsmt uid ...
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 {
			continue
		}
		switch fields[3] {
		case "01", "04", "05": // ESTABLISHED, FIN_WAIT1, FIN_WAIT2
		default:
			continue
		}
		clientIP, clientPort, ok := parseProcNetAddress(fields[1])
		if !ok || clientPort != remote.Port || !clientIP.Equal(remote.IP) {
			continue
		}
		serverIP, serverPort, ok := parseProcNetAddress(fields[2])
		if !ok || serverPort != local.Port || !serverIP.Equal(local.IP) {
			continue
		}
		uid, err := strconv.Atoi(fields[7])
		if err != nil || uid < 0 {
			return -1, false, errors.New("malformed uid in the TCP table")
		}
		return uid, true, nil
	}
	return -1, false, scanner.Err()
}

// parseProcNetAddress decodes the ADDRESS:PORT hex form of /proc/net/tcp,
// whose address is little-endian per 32-bit word.
func parseProcNetAddress(value string) (net.IP, int, bool) {
	separator := strings.LastIndexByte(value, ':')
	if separator < 0 {
		return nil, 0, false
	}
	port, err := strconv.ParseUint(value[separator+1:], 16, 16)
	if err != nil {
		return nil, 0, false
	}
	decoded, err := hex.DecodeString(value[:separator])
	if err != nil || (len(decoded) != net.IPv4len && len(decoded) != net.IPv6len) {
		return nil, 0, false
	}
	address := make(net.IP, len(decoded))
	for offset := 0; offset < len(decoded); offset += 4 {
		binary.LittleEndian.PutUint32(address[offset:], binary.BigEndian.Uint32(decoded[offset:]))
	}
	return address, int(port), true
}
