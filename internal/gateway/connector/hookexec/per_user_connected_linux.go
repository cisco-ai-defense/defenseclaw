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

// Test seams for the per-user accept wait (GAP-1121).
var (
	perUserLinuxProcNet    = procSelfNet
	perUserLinuxAcceptWait = 2 * time.Second
	perUserLinuxAcceptPoll = 5 * time.Millisecond
)

var (
	errConnectedSocketNotFound = errors.New("connected gateway server socket was not found")
	errPerUserForeignSocket    = errors.New("connected gateway socket belongs to another account")
	errPerUserSocketUnaccepted = errors.New("connected gateway socket was not accepted in time, so its account is unproven")
)

// connectedTCPSocket is the kernel's row for the server side of one
// connection. accepted is false while the connection waits in the
// listener's accept queue: the row then has no socket inode, and kernels
// that read the owner from that inode report root for it.
type connectedTCPSocket struct {
	uid      int
	accepted bool
}

func verifyPerUserConnectedTuple(client, server *net.TCPAddr) error {
	ctx, cancel := context.WithTimeout(context.Background(), perUserLinuxAcceptWait)
	defer cancel()
	return awaitPerUserLinuxSocket(ctx, perUserLinuxProcNet, client, server, os.Geteuid())
}

// awaitPerUserLinuxSocket proves that this account owns the server side of
// the held connection before any request byte is written. connect() returns
// once the handshake completes, before the gateway calls accept(), and the
// row can be missing for a moment after it; both are waited out, bounded,
// on the same connection (GAP-1121). Nothing short of an accepted row owned
// by this account (or, before accept, the listener's own account on kernels
// that report it) is proof; a row owned by another account refuses at once.
func awaitPerUserLinuxSocket(ctx context.Context, procNet string, client, server *net.TCPAddr, account int) error {
	for {
		socket, err := findConnectedTCPSocket(procNet, client, server)
		switch {
		case err == nil && socket.uid == account && (socket.accepted || account != 0):
			return nil
		case err == nil && (socket.accepted || socket.uid != 0):
			return errPerUserForeignSocket
		case err != nil && !errors.Is(err, errConnectedSocketNotFound):
			return err
		}
		select {
		case <-ctx.Done():
			if err != nil {
				return err
			}
			return errPerUserSocketUnaccepted
		case <-time.After(perUserLinuxAcceptPoll):
		}
	}
}

// findConnectedTCPUID reads the kernel's accepted server socket, identified
// by both endpoints. A listening-port lookup is insufficient: its owner can
// change while the old process still holds this connected client socket.
func findConnectedTCPUID(procNet string, client, server *net.TCPAddr) (int, error) {
	socket, err := findConnectedTCPSocket(procNet, client, server)
	if err != nil {
		return -1, err
	}
	return socket.uid, nil
}

// findConnectedTCPSocket finds the established server-side row of the exact
// connection. An IPv4 connection accepted by a dual-stack (IPv6 wildcard)
// listener is listed only in tcp6, with IPv4-mapped endpoints, so an IPv4
// tuple is looked up in both tables (GAP-1121). A tuple is unique across
// both tables; more than one established match is refused.
func findConnectedTCPSocket(procNet string, client, server *net.TCPAddr) (connectedTCPSocket, error) {
	serverKeys, err := procTCPEndpointKeys(server)
	if err != nil {
		return connectedTCPSocket{}, err
	}
	clientKeys, err := procTCPEndpointKeys(client)
	if err != nil || len(clientKeys) != len(serverKeys) {
		return connectedTCPSocket{}, errors.New("connected gateway endpoints have different address families")
	}
	var found []connectedTCPSocket
	for index, server := range serverKeys {
		client := clientKeys[index]
		rows, err := scanConnectedTCPTable(filepath.Join(procNet, server.table), server.key, client.key)
		if err != nil {
			// A host without IPv6 has no tcp6 table; the IPv4 table is
			// always read first and its errors always count.
			if index > 0 && errors.Is(err, os.ErrNotExist) {
				continue
			}
			return connectedTCPSocket{}, err
		}
		found = append(found, rows...)
	}
	switch len(found) {
	case 0:
		return connectedTCPSocket{}, errConnectedSocketNotFound
	case 1:
		return found[0], nil
	default:
		return connectedTCPSocket{}, errors.New("connected gateway server socket is listed more than once")
	}
}

func scanConnectedTCPTable(path, serverKey, clientKey string) ([]connectedTCPSocket, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("inspect connected gateway sockets: %w", err)
	}
	defer file.Close()
	var found []connectedTCPSocket
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
			return nil, errors.New("connected gateway socket owner is invalid")
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			return nil, errors.New("connected gateway socket inode is invalid")
		}
		found = append(found, connectedTCPSocket{uid: uid, accepted: inode != 0})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("inspect connected gateway sockets: %w", err)
	}
	return found, nil
}

type procTCPKey struct{ key, table string }

// procTCPEndpointKeys lists the /proc/net encodings of one endpoint: an IPv4
// address as itself in tcp and IPv4-mapped in tcp6, an IPv6 address in tcp6.
func procTCPEndpointKeys(addr *net.TCPAddr) ([]procTCPKey, error) {
	key, table, err := procTCPEndpoint(addr)
	if err != nil {
		return nil, err
	}
	keys := []procTCPKey{{key: key, table: table}}
	if table == "tcp" {
		keys = append(keys, procTCPKey{key: encodeProcTCPEndpoint(addr.IP.To4().To16(), addr.Port), table: "tcp6"})
	}
	return keys, nil
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
	return encodeProcTCPEndpoint(ip, addr.Port), table, nil
}

// encodeProcTCPEndpoint writes ip as /proc/net does: each 32-bit word in
// host (little-endian) byte order, then the port in hex.
func encodeProcTCPEndpoint(ip net.IP, port int) string {
	var encoded strings.Builder
	for offset := 0; offset < len(ip); offset += 4 {
		for index := offset + 3; index >= offset; index-- {
			fmt.Fprintf(&encoded, "%02X", ip[index])
		}
	}
	return fmt.Sprintf("%s:%04X", encoded.String(), port)
}
