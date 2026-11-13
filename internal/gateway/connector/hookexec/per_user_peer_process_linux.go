// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"bufio"
	"context"
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
	return perUserConnectedPeerPIDWithin(context.Background(), client, server)
}

func perUserConnectedPeerPIDWithin(ctx context.Context, client, server *net.TCPAddr) (int, bool) {
	serverKey, table, err := procTCPEndpoint(server)
	if err != nil {
		return 0, false
	}
	clientKey, clientTable, err := procTCPEndpoint(client)
	if err != nil || clientTable != table {
		return 0, false
	}
	inode := ""
	if sock, ok := exactAcceptedSocket(client, server); ok {
		// The one ESTABLISHED socket of this tuple: the procfs rows hold no
		// other, so the tables are not read.
		if int(sock.UID) == os.Geteuid() && sock.Inode != 0 {
			inode = strconv.FormatUint(uint64(sock.Inode), 10)
		}
	} else {
		inode = procSocketInode(table, "01", serverKey, clientKey)
		if inode == "" && table == "tcp" {
			inode = procSocketInode("tcp6", "01", mappedTCP6Endpoint(server), mappedTCP6Endpoint(client))
		}
	}
	// More than one holder of the accepted socket (a dup in another
	// process) is no known peer (review r3 finding 2).
	holders := procSocketHolders(ctx, inode)
	if ctx.Err() != nil || len(holders) != 1 {
		return 0, false
	}
	return holders[0], true
}

// perUserListenerOwners is every process of this account that holds a
// listener on server's address now (exact, or the wildcard of its family),
// with its identity; false when there is none or the read did not finish.
func perUserListenerOwners(ctx context.Context, server *net.TCPAddr) ([]perUserPeerProcess, bool) {
	serverKey, table, err := procTCPEndpoint(server)
	if err != nil {
		return nil, false
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
	holders := procSocketHolders(ctx, inode)
	if len(holders) == 0 || ctx.Err() != nil {
		return nil, false
	}
	owners := make([]perUserPeerProcess, 0, len(holders))
	for _, pid := range holders {
		identity, _ := procidentity.Of(pid)
		owners = append(owners, perUserPeerProcess{pid: pid, identity: identity, server: server})
	}
	return owners, true
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

// procSocketHolders is every process of this account that holds socket
// inode, until ctx ends, in no particular order.
//
// Every per-user hook call runs it once, when its connection is proven
// (PerUserPeerRecord.capture), so it reads only names: no sorting of /proc or
// of a process's fd folder and no FileInfo per entry, which were a third of
// its CPU in a 32-way hook burst (rel-1-0-6 GAP-0381). The holders are the
// same: an unreadable /proc gives none, and a process whose folder or fd
// list cannot be read is skipped.
func procSocketHolders(ctx context.Context, inode string) []int {
	if inode == "" {
		return nil
	}
	want := "socket:[" + inode + "]"
	names, err := readDirNames("/proc")
	if err != nil {
		return nil
	}
	uid := uint32(os.Geteuid())
	var holders []int
	for _, name := range names {
		if ctx.Err() != nil {
			return nil
		}
		pid, err := strconv.Atoi(name)
		if err != nil || pid <= 0 {
			continue
		}
		dir := "/proc/" + name
		var st syscall.Stat_t
		if err := syscall.Stat(dir, &st); err != nil || st.Uid != uid {
			continue
		}
		fdDir := dir + "/fd/"
		fds, err := readDirNames(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			if link, err := os.Readlink(fdDir + fd); err == nil && link == want {
				holders = append(holders, pid)
				break
			}
		}
	}
	return holders
}

// readDirNames is the names in dir, unsorted; an error for a folder that
// cannot be read to its end (os.ReadDir also fails then).
func readDirNames(dir string) ([]string, error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.Readdirnames(-1)
}
