// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// procSelfNet holds this network namespace's socket tables. /proc/net is
// only a symlink to it, and a /proc mounted subset=pid (ProcSubset=pid) has
// no /proc/net, while /proc/self is always there, hidepid included
// (GAP-1138).
const procSelfNet = "/proc/self/net"

func verifyPerUserConnectedTuple(client, server *net.TCPAddr) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return awaitPerUserLinuxSocket(ctx, os.Geteuid(), func() (int, error) {
		return findConnectedTCPUID(procSelfNet, client, server)
	})
}

// Connect can finish before the gateway accepts the same held socket. Until
// accept() gives the accepted socket a file, its procfs row has inode 0 and
// the kernel may report UID 0 for it (sock_i_uid without a socket file), so
// that row proves nothing, not even for a root caller. Only an accepted
// row's real owner is proof; a foreign owner after accept is final.
func awaitPerUserLinuxSocket(ctx context.Context, self int, inspect func() (int, error)) error {
	lastErr := errConnectedSocketNotFound
	for {
		if ctx.Err() != nil {
			return lastErr
		}
		uid, err := inspect()
		switch {
		case err == nil && uid == self:
			return nil
		case err == nil:
			return errors.New("connected gateway socket belongs to another account")
		case errors.Is(err, errConnectedSocketNotFound), errors.Is(err, errConnectedSocketNotAccepted):
			lastErr = err
		default:
			return err
		}
		select {
		case <-ctx.Done():
			return lastErr
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// errConnectedSocketNotAccepted is an exact accepted reverse tuple the
// gateway has not accept()ed yet: its owner is provisional.
var errConnectedSocketNotAccepted = errors.New("connected gateway server socket is not accepted yet")

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
	uid, err := readConnectedTCPUID(procNet, serverTable, clientKey, serverKey)
	if err == nil || !errors.Is(err, errConnectedSocketNotFound) || serverTable != "tcp" {
		return uid, err
	}
	// A dual-stack IPv6 listener records its accepted IPv4 socket in tcp6
	// using IPv4-mapped addresses, even though this client dialed tcp4.
	return readConnectedTCPUID(procNet, "tcp6", mappedTCP6Endpoint(client), mappedTCP6Endpoint(server))
}

func readConnectedTCPUID(procNet, table, clientKey, serverKey string) (int, error) {
	file, err := os.Open(filepath.Join(procNet, table))
	if err != nil {
		if table == "tcp6" && os.IsNotExist(err) {
			return -1, errConnectedSocketNotFound
		}
		return -1, fmt.Errorf("inspect connected gateway sockets: %w", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Scan() // header
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 || fields[3] != "01" ||
			!strings.EqualFold(fields[1], serverKey) || !strings.EqualFold(fields[2], clientKey) {
			continue
		}
		uid, err := strconv.Atoi(fields[7])
		if err != nil || uid < 0 {
			return -1, errors.New("connected gateway socket owner is invalid")
		}
		if inode, err := strconv.ParseUint(fields[9], 10, 64); err != nil {
			return -1, errors.New("connected gateway socket inode is invalid")
		} else if inode == 0 {
			return -1, errConnectedSocketNotAccepted
		}
		return uid, nil
	}
	if err := scanner.Err(); err != nil {
		return -1, fmt.Errorf("inspect connected gateway sockets: %w", err)
	}
	return -1, errConnectedSocketNotFound
}

func mappedTCP6Endpoint(addr *net.TCPAddr) string {
	ip := addr.IP.To4()
	return fmt.Sprintf("0000000000000000FFFF0000%02X%02X%02X%02X:%04X",
		ip[3], ip[2], ip[1], ip[0], addr.Port)
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
