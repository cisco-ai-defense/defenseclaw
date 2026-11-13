// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package peercred

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"
)

func encodeWindowsPort(port int) uint32 { return uint32(port&0xff)<<8 | uint32(port>>8) }

func tcp4Table(rows ...tcpOwnerRow) []byte {
	buf := make([]byte, tcpOwnerTableHeader+len(rows)*tcp4OwnerRowSize)
	binary.LittleEndian.PutUint32(buf, uint32(len(rows)))
	for i, row := range rows {
		r := buf[tcpOwnerTableHeader+i*tcp4OwnerRowSize:]
		binary.LittleEndian.PutUint32(r[0:], row.State)
		copy(r[4:8], row.LocalIP.To4())
		binary.LittleEndian.PutUint32(r[8:], encodeWindowsPort(row.LocalPort))
		copy(r[12:16], row.RemoteIP.To4())
		binary.LittleEndian.PutUint32(r[16:], encodeWindowsPort(row.RemotePort))
		binary.LittleEndian.PutUint32(r[20:], row.PID)
		binary.LittleEndian.PutUint64(r[24:], row.CreateTime)
	}
	return buf
}

func tcp6Table(rows ...tcpOwnerRow) []byte {
	buf := make([]byte, tcpOwnerTableHeader+len(rows)*tcp6OwnerRowSize)
	binary.LittleEndian.PutUint32(buf, uint32(len(rows)))
	for i, row := range rows {
		r := buf[tcpOwnerTableHeader+i*tcp6OwnerRowSize:]
		copy(r[0:16], row.LocalIP.To16())
		binary.LittleEndian.PutUint32(r[20:], encodeWindowsPort(row.LocalPort))
		copy(r[24:40], row.RemoteIP.To16())
		binary.LittleEndian.PutUint32(r[44:], encodeWindowsPort(row.RemotePort))
		binary.LittleEndian.PutUint32(r[48:], row.State)
		binary.LittleEndian.PutUint32(r[52:], row.PID)
		binary.LittleEndian.PutUint64(r[56:], row.CreateTime)
	}
	return buf
}

func TestWindowsTCPTableClientRowMatch(t *testing.T) {
	lo := net.ParseIP("127.0.0.1")
	server := &net.TCPAddr{IP: lo, Port: 18970}
	client := &net.TCPAddr{IP: lo, Port: 51234}
	gatewayRow := tcpOwnerRow{State: mibTCPStateEstab, LocalIP: lo, LocalPort: 18970, RemoteIP: lo, RemotePort: 51234, PID: 900}
	clientEnd := tcpOwnerRow{State: mibTCPStateEstab, LocalIP: lo, LocalPort: 51234, RemoteIP: lo, RemotePort: 18970, PID: 4242}
	otherClient := tcpOwnerRow{State: mibTCPStateEstab, LocalIP: lo, LocalPort: 51235, RemoteIP: lo, RemotePort: 18970, PID: 7}
	closing := clientEnd
	closing.State = 8 // CLOSE_WAIT
	closing.PID = 99

	cases := []struct {
		name    string
		rows    []tcpOwnerRow
		wantPID uint32
		wantErr bool
	}{
		{"client row wins over the server row", []tcpOwnerRow{gatewayRow, otherClient, clientEnd}, 4242, false},
		{"server row alone is never the client", []tcpOwnerRow{gatewayRow}, 0, true},
		{"non-established row is skipped", []tcpOwnerRow{gatewayRow, closing}, 0, true},
		{"two owners are refused", []tcpOwnerRow{clientEnd, func() tcpOwnerRow { r := clientEnd; r.PID = 5555; return r }()}, 0, true},
		{"system process is refused", []tcpOwnerRow{func() tcpOwnerRow { r := clientEnd; r.PID = 4; return r }()}, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := parseTCP4OwnerTable(tcp4Table(tc.rows...))
			if err != nil {
				t.Fatal(err)
			}
			row, err := clientRow(parsed, server, client)
			if (err != nil) != tc.wantErr || row.PID != tc.wantPID {
				t.Fatalf("clientRow = %d, %v; want %d (err %v)", row.PID, err, tc.wantPID, tc.wantErr)
			}
		})
	}
	if _, err := clientRow(nil, server, client); !errors.Is(err, ErrPeerNotFound) {
		t.Fatalf("empty table error = %v, want ErrPeerNotFound", err)
	}
}

func TestWindowsTCP6TableAndMappedAddresses(t *testing.T) {
	lo6 := net.ParseIP("::1")
	server := &net.TCPAddr{IP: lo6, Port: 18970}
	client := &net.TCPAddr{IP: lo6, Port: 40000}
	parsed, err := parseTCP6OwnerTable(tcp6Table(
		tcpOwnerRow{State: mibTCPStateEstab, LocalIP: lo6, LocalPort: 18970, RemoteIP: lo6, RemotePort: 40000, PID: 1},
		tcpOwnerRow{State: mibTCPStateEstab, LocalIP: lo6, LocalPort: 40000, RemoteIP: lo6, RemotePort: 18970, PID: 3131, CreateTime: 1 << 60},
	))
	if err != nil {
		t.Fatal(err)
	}
	if row, err := clientRow(parsed, server, client); err != nil || row.PID != 3131 || row.CreateTime != 1<<60 {
		t.Fatalf("IPv6 client = %+v, %v", row, err)
	}
	// A v4-mapped row of a dual-stack socket matches an IPv4 connection.
	mapped := net.ParseIP("::ffff:127.0.0.1")
	parsed, _ = parseTCP6OwnerTable(tcp6Table(tcpOwnerRow{State: mibTCPStateEstab, LocalIP: mapped, LocalPort: 40001, RemoteIP: mapped, RemotePort: 18970, PID: 77}))
	v4 := net.ParseIP("127.0.0.1").To4()
	if row, err := clientRow(parsed, &net.TCPAddr{IP: v4, Port: 18970}, &net.TCPAddr{IP: v4, Port: 40001}); err != nil || row.PID != 77 {
		t.Fatalf("mapped client = %+v, %v", row, err)
	}
}

func TestWindowsTCPTableTruncated(t *testing.T) {
	buf := tcp4Table(tcpOwnerRow{State: mibTCPStateEstab, LocalIP: net.ParseIP("127.0.0.1"), RemoteIP: net.ParseIP("127.0.0.1")})
	if _, err := parseTCP4OwnerTable(buf[:len(buf)-1]); err == nil {
		t.Fatal("a truncated table must be refused")
	}
	binary.LittleEndian.PutUint32(buf, 1<<30)
	if _, err := parseTCP4OwnerTable(buf); err == nil {
		t.Fatal("a count past the buffer must be refused")
	}
	if _, err := parseTCP6OwnerTable([]byte{1}); err == nil {
		t.Fatal("a short buffer must be refused")
	}
	if got := windowsPort(encodeWindowsPort(18970)); got != 18970 {
		t.Fatalf("port round trip = %d", got)
	}
}

func TestLoopbackTCPPeerSIDRefusesNonLoopback(t *testing.T) {
	if _, err := LoopbackTCPPeerSID(&net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1}, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2}); err == nil {
		t.Fatal("a non-loopback address must be refused")
	}
}
