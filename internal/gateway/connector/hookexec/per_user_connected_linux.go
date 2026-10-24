// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// procSelfNet holds this network namespace's socket tables. /proc/net is
// only a symlink to it, and a /proc mounted subset=pid (ProcSubset=pid) has
// no /proc/net, while /proc/self is always there, hidepid included
// (GAP-1138).
const procSelfNet = "/proc/self/net"

func verifyPerUserConnectedTuple(client, server *net.TCPAddr) error {
	uid, err := findConnectedTCPUID(procSelfNet, client, server)
	if err != nil {
		return err
	}
	if uid != os.Geteuid() {
		return errors.New("connected gateway socket belongs to another account")
	}
	return nil
}

// findConnectedTCPUID reads the kernel's accepted server socket, identified
// by both endpoints. A listening-port lookup is insufficient: its owner can
// change while the old process still holds this connected client socket.
func findConnectedTCPUID(procNet string, client, server *net.TCPAddr) (int, error) {
	serverKey, serverTable, err := procTCPEndpoint(server)
	if err != nil {
		return -1, err
	}
	clientKey, clientTable, err := procTCPEndpoint(client)
	if err != nil || serverTable != clientTable {
		return -1, errors.New("connected gateway endpoints have different address families")
	}
	file, err := os.Open(filepath.Join(procNet, serverTable))
	if err != nil {
		return -1, fmt.Errorf("inspect connected gateway sockets: %w", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Scan() // header
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 || fields[3] != "01" ||
			!strings.EqualFold(fields[1], serverKey) || !strings.EqualFold(fields[2], clientKey) {
			continue
		}
		uid, err := strconv.Atoi(fields[7])
		if err != nil || uid < 0 {
			return -1, errors.New("connected gateway socket owner is invalid")
		}
		return uid, nil
	}
	if err := scanner.Err(); err != nil {
		return -1, fmt.Errorf("inspect connected gateway sockets: %w", err)
	}
	return -1, errors.New("connected gateway server socket was not found")
}

func procTCPEndpoint(addr *net.TCPAddr) (string, string, error) {
	if addr == nil || addr.Port < 1 || addr.Port > 65535 {
		return "", "", errors.New("invalid connected gateway endpoint")
	}
	ip := addr.IP.To4()
	table := "tcp"
	if ip == nil {
		ip = addr.IP.To16()
		table = "tcp6"
	}
	if ip == nil {
		return "", "", errors.New("invalid connected gateway IP")
	}
	var encoded strings.Builder
	for offset := 0; offset < len(ip); offset += 4 {
		for index := offset + 3; index >= offset; index-- {
			fmt.Fprintf(&encoded, "%02X", ip[index])
		}
	}
	return fmt.Sprintf("%s:%04X", encoded.String(), addr.Port), table, nil
}
