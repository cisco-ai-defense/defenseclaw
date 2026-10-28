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

// Test seams. The guard and hooks run as an ordinary user, who can read the
// kernel's socket table with netstat but not the LaunchDaemon account's
// descriptors with lsof (GAP-1138).
var (
	managedDarwinLaunchdPrint = func(ctx context.Context, label string) ([]byte, error) {
		return exec.CommandContext(ctx, "/bin/launchctl", "print", "system/"+label).Output()
	}
	managedDarwinSocketTable = func(ctx context.Context) ([]byte, error) {
		return exec.CommandContext(ctx, "/usr/sbin/netstat", "-anv", "-p", "tcp").Output()
	}
	managedDarwinProcessUID = func(ctx context.Context, pid int) ([]byte, error) {
		return exec.CommandContext(ctx, "/bin/ps", "-o", "uid=", "-p", strconv.Itoa(pid)).Output()
	}
)

// verifyManagedConnectedPeer matches the accepted TCP socket to the active
// gateway LaunchDaemon (root for Secure Client). Checking the listener port
// separately would let a replacement process take it between verification
// and the actual request. The kernel records the process that owns each
// socket, and a socket the gateway has not accepted yet carries its
// listener's process, so the exact accepted tuple names the gateway PID.
func verifyManagedConnectedPeer(parent context.Context, client, server *net.TCPAddr, serviceName string) error {
	if client == nil || server == nil || !client.IP.IsLoopback() || !server.IP.IsLoopback() {
		return errors.New("managed gateway connection is not loopback")
	}
	if serviceName != secureClientGatewayLaunchdLabel && serviceName != standaloneGatewayLaunchdLabel {
		return errors.New("managed gateway service name is untrusted")
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	launchd, err := managedDarwinLaunchdPrint(ctx, serviceName)
	if err != nil {
		return fmt.Errorf("inspect protected gateway LaunchDaemon: %w", err)
	}
	servicePID, err := launchdServicePID(launchd)
	if err != nil {
		return err
	}
	if serviceName == secureClientGatewayLaunchdLabel {
		output, err := managedDarwinProcessUID(ctx, servicePID)
		if err != nil || strings.TrimSpace(string(output)) != "0" {
			return errors.New("secure client gateway LaunchDaemon does not run as root")
		}
	}
	if err := awaitManagedDarwinSocket(ctx, client, server, servicePID); err != nil {
		return err
	}
	relaunchd, err := managedDarwinLaunchdPrint(ctx, serviceName)
	if err != nil {
		return fmt.Errorf("inspect protected gateway LaunchDaemon: %w", err)
	}
	if rechecked, err := launchdServicePID(relaunchd); err != nil || rechecked != servicePID {
		return errors.New("managed gateway service changed during peer verification")
	}
	return nil
}

// awaitManagedDarwinSocket finds the gateway side of the exact tuple. Its
// row can appear just after connect() returns, so a missing row is read
// again until the deadline; a row of another process refuses at once.
func awaitManagedDarwinSocket(ctx context.Context, client, server *net.TCPAddr, servicePID int) error {
	refused := errors.New("connected listener is not the managed gateway service")
	for {
		table, err := managedDarwinSocketTable(ctx)
		if err != nil {
			return fmt.Errorf("inspect connected gateway socket: %w", err)
		}
		pid, err := netstatConnectedPID(table, client, server)
		switch {
		case err == nil && pid == servicePID:
			return nil
		case err == nil || !errors.Is(err, errNetstatTupleMissing):
			return refused
		}
		select {
		case <-ctx.Done():
			return refused
		case <-time.After(20 * time.Millisecond):
		}
	}
}

var errNetstatTupleMissing = errors.New("connected gateway server socket was not found")

// netstatConnectedPID returns the process of the gateway-side socket whose
// local and foreign endpoints are exactly server and client, from
// "netstat -anv -p tcp". The process column ("process:pid", or "pid" on
// older macOS) is found from the header and counted from the end of the row,
// because a process name may hold spaces or colons; its PID follows the last
// colon.
func netstatConnectedPID(table []byte, client, server *net.TCPAddr) (int, error) {
	local := netstatEndpoint(server)
	foreign := netstatEndpoint(client)
	trailing := -1
	for _, line := range strings.Split(string(table), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "Proto" {
			trailing = -1
			for index, name := range fields {
				if name == "process:pid" || name == "pid" {
					trailing = len(fields) - 1 - index
				}
			}
			continue
		}
		if trailing < 0 || fields[0] != "tcp4" || len(fields) < 7+trailing ||
			fields[3] != local || fields[4] != foreign || fields[5] != "ESTABLISHED" {
			continue
		}
		column := fields[len(fields)-1-trailing]
		pid, err := strconv.Atoi(column[strings.LastIndex(column, ":")+1:])
		if err != nil || pid < 1 {
			return 0, errors.New("connected gateway socket process is invalid")
		}
		return pid, nil
	}
	return 0, errNetstatTupleMissing
}

func netstatEndpoint(addr *net.TCPAddr) string {
	if addr == nil || addr.IP.To4() == nil {
		return ""
	}
	return addr.IP.To4().String() + "." + strconv.Itoa(addr.Port)
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
