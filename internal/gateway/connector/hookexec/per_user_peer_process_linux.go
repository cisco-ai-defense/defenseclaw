// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/procidentity"
)

// perUserConnectedPeerPID is the process of this account that holds the
// accepted server socket of the connection client->server: the inode of its
// procfs row, then the process whose open files hold that socket.
func perUserConnectedPeerPID(client, server *net.TCPAddr) (int, bool) {
	serverKey, table, err := procTCPEndpoint(server)
	if err != nil {
		return 0, false
	}
	clientKey, clientTable, err := procTCPEndpoint(client)
	if err != nil || clientTable != table {
		return 0, false
	}
	inode := procSocketInode(table, "01", serverKey, clientKey)
	if inode == "" && table == "tcp" {
		inode = procSocketInode("tcp6", "01", mappedTCP6Endpoint(server), mappedTCP6Endpoint(client))
	}
	return procSocketOwner(inode)
}

// perUserListenerOwner is the process of this account that listens on
// server's address now (exact or wildcard listener), with its identity.
func perUserListenerOwner(server *net.TCPAddr) (perUserPeerProcess, bool) {
	serverKey, table, err := procTCPEndpoint(server)
	if err != nil {
		return perUserPeerProcess{}, false
	}
	port := serverKey[strings.LastIndex(serverKey, ":"):]
	keys := []string{serverKey}
	if table == "tcp" {
		keys = append(keys, "00000000"+port)
	}
	inode := ""
	for _, key := range keys {
		if inode = procSocketInode(table, "0A", key, ""); inode != "" {
			break
		}
	}
	if inode == "" && table == "tcp" {
		for _, key := range []string{mappedTCP6Endpoint(server), "00000000000000000000000000000000" + port} {
			if inode = procSocketInode("tcp6", "0A", key, ""); inode != "" {
				break
			}
		}
	}
	pid, ok := procSocketOwner(inode)
	if !ok {
		return perUserPeerProcess{}, false
	}
	identity, ok := procidentity.Of(pid)
	return perUserPeerProcess{pid: pid, identity: identity, server: server}, ok
}

// procSocketInode is the inode of the first row of table in state with
// local address local (and remote address remote, when given), owned by
// this account; "" when there is none.
func procSocketInode(table, state, local, remote string) string {
	f, err := os.Open(filepath.Join(procSelfNet, table))
	if err != nil {
		return ""
	}
	defer f.Close()
	uid := strconv.Itoa(os.Geteuid())
	scanner := bufio.NewScanner(f)
	scanner.Scan()
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 || fields[3] != state || !strings.EqualFold(fields[1], local) ||
			(remote != "" && !strings.EqualFold(fields[2], remote)) || fields[7] != uid || fields[9] == "0" {
			continue
		}
		return fields[9]
	}
	return ""
}

// procSocketOwner is the process of this account that holds socket inode.
func procSocketOwner(inode string) (int, bool) {
	if inode == "" {
		return 0, false
	}
	want := "socket:[" + inode + "]"
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, false
	}
	uid := uint32(os.Geteuid())
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		dir := filepath.Join("/proc", entry.Name())
		info, err := os.Stat(dir)
		if err != nil {
			continue
		}
		if st, ok := info.Sys().(*syscall.Stat_t); !ok || st.Uid != uid {
			continue
		}
		fds, err := os.ReadDir(filepath.Join(dir, "fd"))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			if link, err := os.Readlink(filepath.Join(dir, "fd", fd.Name())); err == nil && link == want {
				return pid, true
			}
		}
	}
	return 0, false
}
