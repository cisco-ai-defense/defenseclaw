// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"strconv"
	"strings"
)

// procNetListener is one listening TCP socket of a /proc/net/tcp or
// /proc/net/tcp6 table.
type procNetListener struct {
	ip   net.IP
	port int
	uid  int
}

// procNetTCPListen is the TCP_LISTEN state in the st column.
const procNetTCPListen = "0A"

// parseProcNetTCP reads the listening sockets of a /proc/net/tcp or
// /proc/net/tcp6 table: sl, local_address (hex address words, then the
// port), rem_address, st, queues, timer, retransmits, uid. Lines that do
// not parse are skipped.
func parseProcNetTCP(data []byte) []procNetListener {
	var out []procNetListener
	for i, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 8 || f[3] != procNetTCPListen {
			continue
		}
		ipHex, portHex, ok := strings.Cut(f[1], ":")
		if !ok {
			continue
		}
		ip := procNetIP(ipHex)
		port, perr := strconv.ParseUint(portHex, 16, 16)
		uid, uerr := strconv.Atoi(f[7])
		if ip == nil || perr != nil || uerr != nil {
			continue
		}
		out = append(out, procNetListener{ip: ip, port: int(port), uid: uid})
	}
	return out
}

// procNetIP decodes an address column: the kernel prints each 32-bit word
// of the network-order address as a host-order integer.
func procNetIP(h string) net.IP {
	if len(h) != 8 && len(h) != 32 {
		return nil
	}
	raw, err := hex.DecodeString(h)
	if err != nil {
		return nil
	}
	ip := make(net.IP, len(raw))
	for w := 0; w < len(raw); w += 4 {
		binary.NativeEndian.PutUint32(ip[w:w+4], binary.BigEndian.Uint32(raw[w:w+4]))
	}
	return ip
}

// apiPortHolder is the uid of a listener that blocks a bind of ip:port (the
// same address, a wildcard on either side, or the IPv4-mapped form). A uid
// other than self is preferred: that is the account to report.
func apiPortHolder(listeners []procNetListener, ip net.IP, port, self int) (int, bool) {
	uid, found := 0, false
	for _, l := range listeners {
		if l.port != port || (!l.ip.Equal(ip) && !l.ip.IsUnspecified() && !ip.IsUnspecified()) {
			continue
		}
		if l.uid != self {
			return l.uid, true
		}
		uid, found = l.uid, true
	}
	return uid, found
}

// apiBindIP is the address part of a bind address (localhost is
// 127.0.0.1, an empty host is the wildcard).
func apiBindIP(addr string) (net.IP, int, bool) {
	host, rawPort, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, 0, false
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil || port <= 0 || port > 65535 {
		return nil, 0, false
	}
	switch host {
	case "localhost":
		return net.IPv4(127, 0, 0, 1), port, true
	case "":
		return net.IPv4zero, port, true
	}
	ip := net.ParseIP(host)
	return ip, port, ip != nil
}
