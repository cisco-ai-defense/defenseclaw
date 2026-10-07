//go:build darwin

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
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// The records of the net.inet.tcp.pcblist_n sysctl (xnu bsd/netinet/in_pcb.h
// and bsd/sys/socketvar.h, laid out under #pragma pack(4)). Every record
// starts with its length and kind and is padded to 8 bytes; one connection is an xinpcb_n, an xsocket_n and the
// buffer, statistics and tcpcb records, after an xinpgen header and before an
// xinpgen trailer. The xsocket_n so_pcb is the xinpcb_n xi_inpp of its
// connection.
const (
	darwinXSOSocket = 0x001
	darwinXSOInpcb  = 0x010

	darwinXinpgenLen = 24

	darwinInpcbInpp     = 8
	darwinInpcbFport    = 16
	darwinInpcbLport    = 18
	darwinInpcbVflag    = 44
	darwinInpcbFaddr    = 48
	darwinInpcbLaddr    = 64
	darwinInpcbMinLen   = 80
	darwinInpIPv4       = 0x1
	darwinSocketPcb     = 28
	darwinSocketProto   = 36
	darwinSocketFamily  = 40
	darwinSocketUID     = 64
	darwinSocketMinLen  = 68
	darwinIPProtocolTCP = 6
)

func loopbackTCPOwner(local, remote *net.TCPAddr) (int, error) {
	table, err := unix.SysctlRaw("net.inet.tcp.pcblist_n")
	if err != nil {
		return -1, fmt.Errorf("peercred: read the TCP table: %w", err)
	}
	return darwinTCPTableOwner(table, local, remote)
}

// darwinTCPTableOwner finds the client's socket: its local end is the
// client's address and its foreign end the address the connection was
// accepted on.
func darwinTCPTableOwner(table []byte, local, remote *net.TCPAddr) (int, error) {
	if len(table) < darwinXinpgenLen {
		return -1, errors.New("peercred: the TCP table is truncated")
	}
	type socket struct {
		uid      int
		protocol uint32
		family   uint32
	}
	var client []uint64
	sockets := map[uint64]socket{}
	offset := roundUp8(int(binary.LittleEndian.Uint32(table)))
	for offset+8 <= len(table) {
		length := int(binary.LittleEndian.Uint32(table[offset:]))
		kind := binary.LittleEndian.Uint32(table[offset+4:])
		if length <= darwinXinpgenLen || offset+length > len(table) {
			break // the xinpgen trailer
		}
		record := table[offset : offset+length]
		switch {
		case kind == darwinXSOInpcb && length >= darwinInpcbMinLen:
			if darwinInpcbIs(record, remote, local) {
				client = append(client, binary.LittleEndian.Uint64(record[darwinInpcbInpp:]))
			}
		case kind == darwinXSOSocket && length >= darwinSocketMinLen:
			sockets[binary.LittleEndian.Uint64(record[darwinSocketPcb:])] = socket{
				uid:      int(binary.LittleEndian.Uint32(record[darwinSocketUID:])),
				protocol: binary.LittleEndian.Uint32(record[darwinSocketProto:]),
				family:   binary.LittleEndian.Uint32(record[darwinSocketFamily:]),
			}
		}
		offset += roundUp8(length)
	}
	for _, pcb := range client {
		owner, ok := sockets[pcb]
		if !ok {
			continue
		}
		if owner.protocol != darwinIPProtocolTCP || (owner.family != unix.AF_INET && owner.family != unix.AF_INET6) {
			return -1, errors.New("peercred: the TCP table has an unexpected layout")
		}
		return owner.uid, nil
	}
	return -1, ErrPeerNotFound
}

// darwinInpcbIs reports whether an xinpcb_n is the socket bound to localEnd
// and connected to foreignEnd.
func darwinInpcbIs(record []byte, localEnd, foreignEnd *net.TCPAddr) bool {
	if int(binary.BigEndian.Uint16(record[darwinInpcbLport:])) != localEnd.Port ||
		int(binary.BigEndian.Uint16(record[darwinInpcbFport:])) != foreignEnd.Port {
		return false
	}
	address := func(at int) net.IP {
		if record[darwinInpcbVflag]&darwinInpIPv4 != 0 {
			return net.IP(append([]byte(nil), record[at+12:at+16]...))
		}
		return net.IP(append([]byte(nil), record[at:at+16]...))
	}
	return address(darwinInpcbLaddr).Equal(localEnd.IP) && address(darwinInpcbFaddr).Equal(foreignEnd.IP)
}

func roundUp8(n int) int { return (n + 7) &^ 7 }
