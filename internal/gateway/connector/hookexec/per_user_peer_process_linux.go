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
	return soleSocketHolder(ctx, connectedSocketInode(client, server))
}

// perUserGatewayPeerPID is perUserConnectedPeerPIDWithin that first asks the
// one process the call expects: the gateway the gateway.pid record in one of
// homes names. When that process is still the recorded one (kernel start
// identity, before and after its files are read), belongs to this account and
// holds the accepted socket, it is the peer, and no other process is read.
// Every other outcome (no record, a stale or foreign record, a reused pid, a
// socket that process does not hold, a read error) walks every process of the
// account as before, and the walk's rules decide (one holder or none).
//
// The walk also refuses a socket with a second holder of this account. The
// first look does not see one beside the recorded gateway: such a copy needs
// the gateway to hand it over (it does not: accepted sockets are close-on-exec
// and never sent) or ptrace rights over the gateway, which already allow more
// than any outcome the proof can give (S8 DESIGN section 15).
func perUserGatewayPeerPID(ctx context.Context, homes []string, client, server *net.TCPAddr) (int, bool) {
	inode := connectedSocketInode(client, server)
	if inode == "" {
		return 0, false
	}
	for _, home := range homes {
		if pid, ok := recordedGatewayHolds(home, inode); ok {
			if ctx.Err() != nil {
				return 0, false
			}
			return pid, true
		}
	}
	return soleSocketHolder(ctx, inode)
}

// recordedGatewayHolds is the pid of the gateway the record in home names
// when that process, still the recorded one before and after its descriptor
// folder is read, is of this account and holds socket inode.
func recordedGatewayHolds(home, inode string) (int, bool) {
	record, ok := readGatewayRecord(home)
	if !ok || !procidentity.IsRecorded(record.PID, record.StartIdentity) {
		return 0, false
	}
	if !procHoldsSocket(strconv.Itoa(record.PID), uint32(os.Geteuid()), "socket:["+inode+"]") {
		return 0, false
	}
	// The pid was not reused while its files were read.
	if !procidentity.IsRecorded(record.PID, record.StartIdentity) {
		return 0, false
	}
	return record.PID, true
}

// soleSocketHolder is the one process of this account that holds inode,
// false when there is none, more than one, or ctx ended first.
func soleSocketHolder(ctx context.Context, inode string) (int, bool) {
	// More than one holder of the accepted socket (a dup in another
	// process) is no known peer (review r3 finding 2).
	holders := socketHolderWalk(ctx, inode)
	if ctx.Err() != nil || len(holders) != 1 {
		return 0, false
	}
	return holders[0], true
}

// socketHolderWalk is procSocketHolders; a test counts the walks.
var socketHolderWalk = procSocketHolders

// connectedSocketInode is the inode of the accepted server socket of
// client->server when this account owns it, "" otherwise.
func connectedSocketInode(client, server *net.TCPAddr) string {
	serverKey, table, err := procTCPEndpoint(server)
	if err != nil {
		return ""
	}
	clientKey, clientTable, err := procTCPEndpoint(client)
	if err != nil || clientTable != table {
		return ""
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
	return inode
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
		if procHoldsSocket(name, uid, want) {
			holders = append(holders, pid)
		}
	}
	return holders
}

// procHoldsSocket reports whether /proc/<name> is a process of account uid
// with link want (socket:[inode]) in its descriptor folder. A folder that
// cannot be read is false. Callers pass the effective uid; readGatewayRecord
// checks the record file against the real uid. The hook binaries are never
// setuid, so the two are the same account (A2 review P4).
func procHoldsSocket(name string, uid uint32, want string) bool {
	dir := "/proc/" + name
	var st syscall.Stat_t
	if err := syscall.Stat(dir, &st); err != nil || st.Uid != uid {
		return false
	}
	fdDir := dir + "/fd/"
	fds, err := readDirNames(fdDir)
	if err != nil {
		return false
	}
	for _, fd := range fds {
		if link, err := os.Readlink(fdDir + fd); err == nil && link == want {
			return true
		}
	}
	return false
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
