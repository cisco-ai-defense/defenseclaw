// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package hookexec

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/procidentity"
)

// perUserLsofPairs lists this account's sockets on server in state as
// (pid, name) pairs, every p/n pair lsof -F pn prints.
func perUserLsofPairs(ctx context.Context, server *net.TCPAddr, state string) [][2]string {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	filter := "-iTCP@" + net.JoinHostPort(server.IP.String(), strconv.Itoa(server.Port))
	out, err := exec.CommandContext(ctx, "/usr/sbin/lsof", "-nP", "-a", "-u", strconv.Itoa(os.Geteuid()),
		filter, "-sTCP:"+state, "-Fpn").Output()
	if err != nil {
		return nil
	}
	var pairs [][2]string
	pid := ""
	for _, line := range strings.Split(string(out), "\n") {
		if len(line) < 2 {
			continue
		}
		switch line[0] {
		case 'p':
			pid = line[1:]
		case 'n':
			if pid != "" {
				pairs = append(pairs, [2]string{pid, line[1:]})
			}
		}
	}
	return pairs
}

// perUserConnectedPeerPID is the one process of this account that holds the
// server end of the connection client->server; more than one is unknown.
func perUserConnectedPeerPID(client, server *net.TCPAddr) (int, bool) {
	want := net.JoinHostPort(server.IP.String(), strconv.Itoa(server.Port)) + "->" +
		net.JoinHostPort(client.IP.String(), strconv.Itoa(client.Port))
	found := map[int]bool{}
	for _, pair := range perUserLsofPairs(context.Background(), server, "ESTABLISHED") {
		pid, err := strconv.Atoi(pair[0])
		if err == nil && pid > 0 && connectedSocketNameMatches(pair[1], want) {
			found[pid] = true
		}
	}
	if len(found) != 1 {
		return 0, false
	}
	for pid := range found {
		return pid, true
	}
	return 0, false
}

// perUserListenerOwners is every process of this account that listens on
// exactly server's host:port now (review r3 finding 1: a wildcard listener
// lsof may list beside it is not the gateway address), with its identity.
func perUserListenerOwners(ctx context.Context, server *net.TCPAddr) ([]perUserPeerProcess, bool) {
	want := net.JoinHostPort(server.IP.String(), strconv.Itoa(server.Port))
	seen := map[int]bool{}
	var owners []perUserPeerProcess
	for _, pair := range perUserLsofPairs(ctx, server, "LISTEN") {
		pid, err := strconv.Atoi(pair[0])
		if err != nil || pid <= 0 || seen[pid] || pair[1] != want {
			continue
		}
		seen[pid] = true
		identity, _ := procidentity.Of(pid)
		owners = append(owners, perUserPeerProcess{pid: pid, identity: identity, server: server})
	}
	return owners, len(owners) > 0 && ctx.Err() == nil
}
