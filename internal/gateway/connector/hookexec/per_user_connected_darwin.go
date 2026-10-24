// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package hookexec

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// verifyLocalPeerTuple is VerifyLocalPeer on macOS: lsof run as this account
// lists only its own sockets, so only this account's socket is proven (Docker
// Desktop's port proxy runs as the signed-in account).
func verifyLocalPeerTuple(client, server *net.TCPAddr) error {
	return verifyPerUserConnectedTuple(client, server)
}

func verifyPerUserConnectedTuple(client, server *net.TCPAddr) error {
	if client == nil || server == nil {
		return errors.New("connected gateway endpoint is missing")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	filter := "-iTCP@" + net.JoinHostPort(server.IP.String(), strconv.Itoa(server.Port))
	output, err := exec.CommandContext(ctx, "/usr/sbin/lsof", "-nP", "-a", "-u", strconv.Itoa(os.Geteuid()),
		filter, "-sTCP:ESTABLISHED", "-Fpcun").Output()
	if err != nil {
		return fmt.Errorf("inspect connected gateway socket: %w", err)
	}
	want := net.JoinHostPort(server.IP.String(), strconv.Itoa(server.Port)) + "->" +
		net.JoinHostPort(client.IP.String(), strconv.Itoa(client.Port))
	owner := -1
	for _, line := range strings.Split(string(output), "\n") {
		if len(line) < 2 {
			continue
		}
		switch line[0] {
		case 'p':
			owner = -1
		case 'u':
			owner, _ = strconv.Atoi(line[1:])
		case 'n':
			if owner == os.Geteuid() && connectedSocketNameMatches(line[1:], want) {
				return nil
			}
		}
	}
	return errors.New("connected gateway server socket was not proven to belong to this account")
}
