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

// perUserLsof lists this account's sockets on server in state (lsof -F pn).
func perUserLsof(server *net.TCPAddr, state string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	filter := "-iTCP@" + net.JoinHostPort(server.IP.String(), strconv.Itoa(server.Port))
	out, err := exec.CommandContext(ctx, "/usr/sbin/lsof", "-nP", "-a", "-u", strconv.Itoa(os.Geteuid()),
		filter, "-sTCP:"+state, "-Fpn").Output()
	if err != nil {
		return nil
	}
	return strings.Split(string(out), "\n")
}

// perUserConnectedPeerPID is the process of this account that holds the
// server end of the connection client->server.
func perUserConnectedPeerPID(client, server *net.TCPAddr) (int, bool) {
	want := net.JoinHostPort(server.IP.String(), strconv.Itoa(server.Port)) + "->" +
		net.JoinHostPort(client.IP.String(), strconv.Itoa(client.Port))
	pid := 0
	for _, line := range perUserLsof(server, "ESTABLISHED") {
		if len(line) < 2 {
			continue
		}
		switch line[0] {
		case 'p':
			pid, _ = strconv.Atoi(line[1:])
		case 'n':
			if pid > 0 && connectedSocketNameMatches(line[1:], want) {
				return pid, true
			}
		}
	}
	return 0, false
}

// perUserListenerOwner is the process of this account that listens on
// server's port now, with its identity.
func perUserListenerOwner(server *net.TCPAddr) (perUserPeerProcess, bool) {
	for _, line := range perUserLsof(server, "LISTEN") {
		if len(line) > 1 && line[0] == 'p' {
			pid, err := strconv.Atoi(line[1:])
			if err != nil || pid <= 0 {
				continue
			}
			identity, ok := procidentity.Of(pid)
			return perUserPeerProcess{pid: pid, identity: identity, server: server}, ok
		}
	}
	return perUserPeerProcess{}, false
}
