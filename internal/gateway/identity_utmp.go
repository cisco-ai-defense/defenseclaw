// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/binary"
	"net"
)

// utmp records (glibc struct utmp on 64-bit Linux, 384 bytes, little or
// big endian as the host). Only login records are read: the gateway uses
// /run/utmp to confirm that a claimed terminal belongs to the verified user
// when logind cannot answer.

const (
	utmpRecordSize  = 384
	utmpUserProcess = 7
	utmpLineOffset  = 8
	utmpLineSize    = 32
	utmpUserOffset  = 44
	utmpUserSize    = 32
	utmpHostOffset  = 76
	utmpHostSize    = 256
	utmpAddrOffset  = 348
	utmpMaxBytes    = 4 << 20
)

type utmpEntry struct {
	PID  int32
	Line string
	User string
	Host string
	Addr net.IP
}

// parseUtmp returns the USER_PROCESS records of a utmp file.
func parseUtmp(data []byte, order binary.ByteOrder) []utmpEntry {
	if len(data) > utmpMaxBytes {
		data = data[:utmpMaxBytes]
	}
	var out []utmpEntry
	for off := 0; off+utmpRecordSize <= len(data); off += utmpRecordSize {
		rec := data[off : off+utmpRecordSize]
		if int16(order.Uint16(rec[0:2])) != utmpUserProcess {
			continue
		}
		entry := utmpEntry{
			PID:  int32(order.Uint32(rec[4:8])),
			Line: utmpString(rec[utmpLineOffset : utmpLineOffset+utmpLineSize]),
			User: utmpString(rec[utmpUserOffset : utmpUserOffset+utmpUserSize]),
			Host: utmpString(rec[utmpHostOffset : utmpHostOffset+utmpHostSize]),
		}
		addr := rec[utmpAddrOffset : utmpAddrOffset+16]
		switch {
		case bytes.Equal(addr[4:], make([]byte, 12)) && !bytes.Equal(addr[:4], make([]byte, 4)):
			entry.Addr = net.IP(append([]byte(nil), addr[:4]...)).To4()
		case !bytes.Equal(addr, make([]byte, 16)):
			entry.Addr = net.IP(append([]byte(nil), addr...))
		}
		if entry.Line != "" && entry.User != "" {
			out = append(out, entry)
		}
	}
	return out
}

func utmpString(field []byte) string {
	if i := bytes.IndexByte(field, 0); i >= 0 {
		field = field[:i]
	}
	return string(field)
}
