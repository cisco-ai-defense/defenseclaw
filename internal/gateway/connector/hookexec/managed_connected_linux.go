// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

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

const managedLinuxGatewayService = "defenseclaw-gateway.service"

// verifyManagedConnectedPeer binds the accepted TCP tuple to the UID of the
// running, packaged systemd gateway. The service account is dedicated to
// DefenseClaw; a different local account cannot create a socket with its UID.
// The systemd PID is checked again after the socket lookup to reject restart
// races. A Secure Client TCP gateway is not installed on Linux.
func verifyManagedConnectedPeer(parent context.Context, client, server *net.TCPAddr, serviceName string) error {
	if serviceName != managedLinuxGatewayService || client == nil || server == nil ||
		!client.IP.IsLoopback() || !server.IP.IsLoopback() {
		return errors.New("managed gateway service or connected endpoint is untrusted")
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	pid, err := managedLinuxServicePID(ctx)
	if err != nil {
		return err
	}
	image, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil || image != "/opt/defenseclaw/bin/defenseclaw-gateway" {
		return errors.New("managed gateway service executable is unverified")
	}
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return fmt.Errorf("inspect managed gateway service account: %w", err)
	}
	serviceUID, err := effectiveUIDFromProcStatus(status)
	if err != nil {
		return err
	}
	socketUID, err := findConnectedTCPUID("/proc/net", client, server)
	if err != nil || socketUID != serviceUID {
		return errors.New("connected gateway socket does not belong to the managed service account")
	}
	recheckedPID, err := managedLinuxServicePID(ctx)
	if err != nil || recheckedPID != pid {
		return errors.New("managed gateway service changed during peer verification")
	}
	return nil
}

func managedLinuxServicePID(ctx context.Context) (int, error) {
	output, err := exec.CommandContext(ctx, "/usr/bin/systemctl", "--system", "show", "--property=MainPID", "--value", managedLinuxGatewayService).Output()
	if err != nil {
		return 0, fmt.Errorf("inspect protected gateway service: %w", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(output)))
	if err != nil || pid < 1 {
		return 0, errors.New("managed gateway service is not running")
	}
	return pid, nil
}

func effectiveUIDFromProcStatus(data []byte) (int, error) {
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "Uid:"))
		if len(fields) != 4 {
			break
		}
		uid, err := strconv.Atoi(fields[1])
		if err == nil && uid >= 0 {
			return uid, nil
		}
		break
	}
	return -1, errors.New("managed gateway service UID is unavailable")
}
