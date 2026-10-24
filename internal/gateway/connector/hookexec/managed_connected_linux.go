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
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	managedLinuxGatewayService    = "defenseclaw-gateway.service"
	managedLinuxGatewayExecutable = "/opt/defenseclaw/bin/defenseclaw-gateway"
)

// Test seams. The guard and hooks run as an ordinary user, so every probe
// here must work without root or ptrace access to the service account.
var (
	managedLinuxServiceShow = systemctlShowManagedGateway
	managedLinuxProcRoot    = "/proc"
	managedLinuxAcceptPoll  = 5 * time.Millisecond
)

// verifyManagedConnectedPeer binds the accepted TCP tuple to the UID of the
// running, packaged systemd gateway. The service account is dedicated to
// DefenseClaw; a different local account cannot create a socket with its UID.
// The systemd PID is checked again after the socket lookup to reject restart
// races. A Secure Client TCP gateway is not installed on Linux.
//
// The executable comes from the unit systemd started (only root can change
// the unit or /opt/defenseclaw), not from /proc/<pid>/exe: that link needs
// ptrace access to the service account, so an ordinary user's ACP guard or
// hook could never read it and refused every verified gateway (GAP-1138).
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
	status, err := os.ReadFile(filepath.Join(managedLinuxProcRoot, strconv.Itoa(pid), "status"))
	if err != nil {
		return fmt.Errorf("inspect managed gateway service account: %w", err)
	}
	serviceUID, err := effectiveUIDFromProcStatus(status)
	if err != nil {
		return err
	}
	if err := awaitManagedServiceSocket(ctx, client, server, serviceUID); err != nil {
		return err
	}
	recheckedPID, err := managedLinuxServicePID(ctx)
	if err != nil || recheckedPID != pid {
		return errors.New("managed gateway service changed during peer verification")
	}
	return nil
}

// awaitManagedServiceSocket waits for the gateway to accept this connection.
// connect() returns once the kernel completes the handshake, before the
// gateway calls accept(); until then the server socket has no owning file
// and /proc/net/tcp reports it as root (systemd also creates the activated
// listener as root). Root is never taken as proof, because an impostor's
// unaccepted socket reads the same; only the service UID is, and any other
// account refuses at once.
func awaitManagedServiceSocket(ctx context.Context, client, server *net.TCPAddr, serviceUID int) error {
	refused := errors.New("connected gateway socket does not belong to the managed service account")
	for {
		uid, err := findConnectedTCPUID(filepath.Join(managedLinuxProcRoot, "net"), client, server)
		switch {
		case err == nil && uid == serviceUID:
			return nil
		case err == nil && uid != 0:
			return refused
		}
		select {
		case <-ctx.Done():
			return refused
		case <-time.After(managedLinuxAcceptPoll):
		}
	}
}

func systemctlShowManagedGateway(ctx context.Context) ([]byte, error) {
	return exec.CommandContext(ctx, "/usr/bin/systemctl", "--system", "show",
		"--property=MainPID", "--property=ExecStart", managedLinuxGatewayService).Output()
}

// managedLinuxServicePID returns the main PID of the gateway unit when that
// unit starts the packaged gateway executable.
func managedLinuxServicePID(ctx context.Context) (int, error) {
	output, err := managedLinuxServiceShow(ctx)
	if err != nil {
		return 0, fmt.Errorf("inspect protected gateway service: %w", err)
	}
	pid, executable := 0, ""
	for _, line := range strings.Split(string(output), "\n") {
		key, value, _ := strings.Cut(strings.TrimSpace(line), "=")
		switch key {
		case "MainPID":
			pid, err = strconv.Atoi(value)
			if err != nil {
				pid = 0
			}
		case "ExecStart":
			executable = execStartPath(value)
		}
	}
	if pid < 1 {
		return 0, errors.New("managed gateway service is not running")
	}
	if executable != managedLinuxGatewayExecutable {
		return 0, errors.New("managed gateway service executable is unverified")
	}
	return pid, nil
}

// execStartPath reads path= from systemd's ExecStart property,
// "{ path=/x ; argv[]=/x ; ... }". Several commands are not the packaged unit.
func execStartPath(value string) string {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "{ ") || !strings.HasSuffix(value, " }") || strings.Count(value, "{") != 1 {
		return ""
	}
	for _, field := range strings.Split(strings.TrimSuffix(strings.TrimPrefix(value, "{ "), " }"), " ; ") {
		if path, ok := strings.CutPrefix(field, "path="); ok {
			return path
		}
	}
	return ""
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
