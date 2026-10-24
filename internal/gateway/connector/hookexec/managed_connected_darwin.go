// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package hookexec

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	secureClientGatewayLaunchdLabel = "com.cisco.secureclient.defenseclaw"
	standaloneGatewayLaunchdLabel   = "com.cisco.defenseclaw.gateway"
)

// verifyManagedConnectedPeer matches the accepted TCP socket to the active
// root-owned Secure Client gateway LaunchDaemon. Checking the listener port
// separately would let a replacement process take it between verification
// and the actual request.
func verifyManagedConnectedPeer(parent context.Context, client, server *net.TCPAddr, serviceName string) error {
	if client == nil || server == nil || !client.IP.IsLoopback() || !server.IP.IsLoopback() {
		return errors.New("managed gateway connection is not loopback")
	}
	if serviceName != secureClientGatewayLaunchdLabel && serviceName != standaloneGatewayLaunchdLabel {
		return errors.New("managed gateway service name is untrusted")
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	launchd, err := exec.CommandContext(ctx, "/bin/launchctl", "print", "system/"+serviceName).Output()
	if err != nil {
		return fmt.Errorf("inspect protected gateway LaunchDaemon: %w", err)
	}
	servicePID, err := launchdServicePID(launchd)
	if err != nil {
		return err
	}
	filter := "-iTCP@" + net.JoinHostPort(server.IP.String(), strconv.Itoa(server.Port))
	output, err := exec.CommandContext(ctx, "/usr/sbin/lsof", "-nP", "-a", "-p", strconv.Itoa(servicePID),
		filter, "-sTCP:ESTABLISHED", "-Fpcun").Output()
	if err != nil {
		return fmt.Errorf("inspect connected gateway socket: %w", err)
	}
	want := net.JoinHostPort(server.IP.String(), strconv.Itoa(server.Port)) + "->" +
		net.JoinHostPort(client.IP.String(), strconv.Itoa(client.Port))
	pid, uid := 0, -1
	for _, line := range strings.Split(string(output), "\n") {
		if len(line) < 2 {
			continue
		}
		switch line[0] {
		case 'p':
			pid, _ = strconv.Atoi(line[1:])
			uid = -1
		case 'u':
			uid, _ = strconv.Atoi(line[1:])
		case 'n':
			if pid == servicePID && uid >= 0 &&
				(serviceName != secureClientGatewayLaunchdLabel || uid == 0) &&
				connectedSocketNameMatches(line[1:], want) {
				return nil
			}
		}
	}
	return errors.New("connected listener is not the Secure Client gateway service")
}

func launchdServicePID(output []byte) (int, error) {
	pid := 0
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "pid = ") {
			continue
		}
		parsed, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "pid = ")))
		if err != nil || parsed < 1 || pid != 0 {
			return 0, errors.New("secure client gateway LaunchDaemon PID is invalid")
		}
		pid = parsed
	}
	if pid == 0 {
		return 0, errors.New("secure client gateway LaunchDaemon is not running")
	}
	return pid, nil
}
