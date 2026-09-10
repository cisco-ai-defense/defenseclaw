// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
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

//go:build linux

package netprobe

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// procNetTables are the connection tables /proc exposes. Both address families
// are read: an IPv6 socket to a provider is the same finding as an IPv4 one,
// and a detector that read only tcp would miss every dual-stack host.
var procNetTables = []string{"/proc/net/tcp", "/proc/net/tcp6"}

// tcpStateEstablished and tcpStateListen are the two hex state codes in
// /proc/net/tcp worth distinguishing.
const (
	tcpStateEstablished = "01"
	tcpStateListen      = "0A"
)

// snapshot reads the connection tables, then maps socket inodes to pids by
// walking /proc/<pid>/fd.
//
// The inode walk is the expensive half and the half that needs privilege: an
// unprivileged run can read every row of /proc/net/tcp but can open only its
// own processes' fd directories, so it sees every connection and can name the
// owner of only its own.
func snapshot() ([]Connection, int, error) {
	rows, err := readConnectionTables()
	if err != nil {
		return nil, 0, err
	}
	wanted := make(map[string]bool, len(rows))
	for index := range rows {
		wanted[rows[index].inode] = true
	}
	owners := socketOwners(wanted)
	unattributed := 0
	for index := range rows {
		if pid, ok := owners[rows[index].inode]; ok {
			rows[index].connection.PID = pid
			continue
		}
		unattributed++
	}
	connections := make([]Connection, 0, len(rows))
	for _, row := range rows {
		connections = append(connections, row.connection)
	}
	return connections, unattributed, nil
}

type inodeRow struct {
	inode      string
	connection Connection
}

func readConnectionTables() ([]inodeRow, error) {
	rows := make([]inodeRow, 0, 256)
	var firstErr error
	for _, path := range procNetTables {
		handle, err := os.Open(path)
		if err != nil {
			// A kernel without IPv6 has no tcp6 table. That is not an error;
			// a missing tcp table is.
			if firstErr == nil && path == procNetTables[0] {
				firstErr = err
			}
			continue
		}
		scanner := bufio.NewScanner(handle)
		scanner.Scan() // header
		for scanner.Scan() {
			if row, ok := parseProcNetLine(scanner.Text()); ok {
				rows = append(rows, row)
			}
		}
		// A scanner stops on the first read error and on any line past its
		// token limit, and the loop above ends normally either way. Silently
		// returning a truncated table means fewer connections and a lower
		// unattributed count than the host actually has -- a partial read
		// rendered as a quiet host, which is the substitution this whole
		// subsystem refuses to make.
		if err := scanner.Err(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("%s: %w", path, err)
		}
		handle.Close()
	}
	if firstErr != nil {
		return rows, firstErr
	}
	return rows, nil
}

// parseProcNetLine decodes one row of /proc/net/tcp{,6}.
func parseProcNetLine(line string) (inodeRow, bool) {
	fields := strings.Fields(line)
	// sl local_address rem_address st tx:rx retrnsmt uid timeout inode ...
	const (
		fieldLocal  = 1
		fieldRemote = 2
		fieldState  = 3
		fieldInode  = 9
	)
	if len(fields) <= fieldInode {
		return inodeRow{}, false
	}
	_, localPort, ok := parseHexAddress(fields[fieldLocal])
	if !ok {
		return inodeRow{}, false
	}
	remoteIP, remotePort, ok := parseHexAddress(fields[fieldRemote])
	if !ok {
		return inodeRow{}, false
	}
	state := StateOther
	switch strings.ToUpper(fields[fieldState]) {
	case tcpStateEstablished:
		state = StateEstablished
	case tcpStateListen:
		state = StateListen
	}
	return inodeRow{
		inode: fields[fieldInode],
		connection: Connection{
			LocalPort: localPort, RemoteIP: remoteIP, RemotePort: remotePort, State: state,
		},
	}, true
}

// parseHexAddress decodes the "ADDRESS:PORT" hex form /proc/net uses.
//
// The address is little-endian per 32-bit word, which is why each 8-hex-digit
// group is reversed independently rather than the whole buffer being flipped.
// An IPv6 address is four such words.
func parseHexAddress(value string) (net.IP, int, bool) {
	separator := strings.LastIndexByte(value, ':')
	if separator < 0 {
		return nil, 0, false
	}
	rawAddress, rawPort := value[:separator], value[separator+1:]
	port, err := strconv.ParseUint(rawPort, 16, 32)
	if err != nil {
		return nil, 0, false
	}
	decoded, err := hex.DecodeString(rawAddress)
	if err != nil || len(decoded)%4 != 0 || len(decoded) == 0 {
		return nil, 0, false
	}
	address := make([]byte, len(decoded))
	for offset := 0; offset < len(decoded); offset += 4 {
		word := binary.BigEndian.Uint32(decoded[offset : offset+4])
		binary.LittleEndian.PutUint32(address[offset:offset+4], word)
	}
	return net.IP(address), int(port), true
}

// socketOwners maps socket inodes to the pid holding them by walking
// /proc/<pid>/fd. Failures are silent by design: a process that exits
// mid-walk, or one this run may not open, is exactly the unattributed case
// the caller counts.
//
// wanted is the set of inodes the connection table actually produced. The
// walk stops once every one is accounted for: a host with thousands of
// processes has far more descriptors than sockets in the TCP table, and
// reading every /proc/<pid>/fd entry to the end is the dominant cost of a
// poll on exactly the machines where a poll should stay cheap.
func socketOwners(wanted map[string]bool) map[string]int {
	owners := make(map[string]int, len(wanted))
	if len(wanted) == 0 {
		return owners
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return owners
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		fdDir := filepath.Join("/proc", entry.Name(), "fd")
		descriptors, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, descriptor := range descriptors {
			target, err := os.Readlink(filepath.Join(fdDir, descriptor.Name()))
			if err != nil {
				continue
			}
			inode, ok := socketInode(target)
			if !ok || !wanted[inode] {
				continue
			}
			owners[inode] = pid
			if len(owners) == len(wanted) {
				// Every socket in the table has an owner; nothing further to
				// find.
				return owners
			}
		}
	}
	return owners
}

func socketInode(link string) (string, bool) {
	const prefix, suffix = "socket:[", "]"
	if !strings.HasPrefix(link, prefix) || !strings.HasSuffix(link, suffix) {
		return "", false
	}
	return link[len(prefix) : len(link)-len(suffix)], true
}
