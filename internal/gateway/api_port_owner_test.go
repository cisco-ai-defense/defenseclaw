// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/binary"
	"net"
	"testing"
)

// A little-endian /proc/net/tcp and tcp6 as Linux prints them.
const (
	procNetTCPFixture = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:4A1A 00000000:0000 0A 00000000:00000000 00:00000000 00000000  4242        0 1234 1 0000000000000000 100 0 0 10 0
   1: 0100007F:4A1A 0100007F:9C40 01 00000000:00000000 00:00000000 00000000  1000        0 0 1 0000000000000000 20 4 30 10 -1
   2: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 99 1 0000000000000000 100 0 0 10 0
   3: garbage
`
	procNetTCP6Fixture = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:4A1B 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  4243        0 5 1 0000000000000000 100 0 0 10 0
   1: 0000000000000000FFFF00000100007F:4A1C 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  4244        0 6 1 0000000000000000 100 0 0 10 0
   2: 00000000000000000000000001000000:4A1D 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  4245        0 7 1 0000000000000000 100 0 0 10 0
`
)

func littleEndianHost() bool { return binary.NativeEndian.Uint16([]byte{1, 0}) == 1 }

func TestParseProcNetTCPListeners(t *testing.T) {
	if !littleEndianHost() {
		t.Skip("fixtures are little-endian /proc output")
	}
	v4 := parseProcNetTCP([]byte(procNetTCPFixture))
	if len(v4) != 2 || !v4[0].ip.Equal(net.IPv4(127, 0, 0, 1)) || v4[0].port != 18970 || v4[0].uid != 4242 {
		t.Fatalf("tcp listeners: %+v", v4)
	}
	if !v4[1].ip.Equal(net.IPv4zero) || v4[1].port != 8080 || v4[1].uid != 0 {
		t.Fatalf("wildcard listener: %+v", v4[1])
	}
	v6 := parseProcNetTCP([]byte(procNetTCP6Fixture))
	if len(v6) != 3 || !v6[0].ip.IsUnspecified() || !v6[1].ip.Equal(net.IPv4(127, 0, 0, 1)) || !v6[2].ip.Equal(net.IPv6loopback) {
		t.Fatalf("tcp6 listeners: %+v", v6)
	}
}

func TestAPIPortHolderMatchesTheBindAddress(t *testing.T) {
	lo := net.IPv4(127, 0, 0, 1)
	l := func(ip net.IP, port, uid int) procNetListener { return procNetListener{ip: ip, port: port, uid: uid} }
	for _, tc := range []struct {
		name      string
		listeners []procNetListener
		bind      net.IP
		uid       int
		found     bool
	}{
		{"same address", []procNetListener{l(lo, 18970, 4242)}, lo, 4242, true},
		{"wildcard v4", []procNetListener{l(net.IPv4zero, 18970, 4242)}, lo, 4242, true},
		{"wildcard v6", []procNetListener{l(net.IPv6unspecified, 18970, 4242)}, lo, 4242, true},
		{"v4-mapped", []procNetListener{l(net.ParseIP("::ffff:127.0.0.1"), 18970, 4242)}, lo, 4242, true},
		{"wildcard bind", []procNetListener{l(net.IPv4(10, 0, 0, 5), 18970, 4242)}, net.IPv4zero, 4242, true},
		{"other address", []procNetListener{l(net.IPv4(127, 0, 0, 2), 18970, 4242)}, lo, 0, false},
		{"other port", []procNetListener{l(lo, 18971, 4242)}, lo, 0, false},
		{"own listener", []procNetListener{l(lo, 18970, 1000)}, lo, 1000, true},
		{"another account wins", []procNetListener{l(lo, 18970, 1000), l(net.IPv4zero, 18970, 4242)}, lo, 4242, true},
	} {
		uid, found := apiPortHolder(tc.listeners, tc.bind, 18970, 1000)
		if uid != tc.uid || found != tc.found {
			t.Fatalf("%s: uid=%d found=%v, want %d %v", tc.name, uid, found, tc.uid, tc.found)
		}
	}
	for _, tc := range []struct {
		addr string
		ip   net.IP
		ok   bool
	}{{"127.0.0.1:18970", net.IPv4(127, 0, 0, 1), true}, {"localhost:18970", net.IPv4(127, 0, 0, 1), true}, {":18970", net.IPv4zero, true}, {"[::1]:18970", net.IPv6loopback, true}, {"host:18970", nil, false}, {"127.0.0.1:0", nil, false}} {
		ip, port, ok := apiBindIP(tc.addr)
		if ok != tc.ok || (ok && (!ip.Equal(tc.ip) || port != 18970)) {
			t.Fatalf("%s: %v %d %v", tc.addr, ip, port, ok)
		}
	}
}
