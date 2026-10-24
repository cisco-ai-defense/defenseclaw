// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"time"
)

const (
	managedLinuxGatewayService    = "defenseclaw-gateway.service"
	managedLinuxGatewayExecutable = "/opt/defenseclaw/bin/defenseclaw-gateway"
	// managedLinuxPeerWait bounds the peer check when the request has no
	// shorter deadline of its own: the gateway may still be starting under
	// socket activation, or not yet have accepted this connection.
	managedLinuxPeerWait = defaultHookRequestTimeout
)

// trustedSystemctlEnv returns the whole environment of every systemctl probe. The
// guard and hooks run in the editor's environment, where
// DBUS_SYSTEM_BUS_ADDRESS, SYSTEMD_* and the like point systemctl at another
// bus or change its output, so a healthy gateway could not answer
// (GAP-1138).
func trustedSystemctlEnv() []string { return []string{"LC_ALL=C", "SYSTEMD_PAGER=cat"} }

// Test seams. The guard and hooks run as an ordinary user, so every probe
// here must work without root, ptrace access or a readable /proc entry of
// the service account (hidepid).
var (
	managedLinuxServiceShow = systemctlShowManagedGateway
	managedLinuxLookupUser  = user.Lookup
	managedLinuxProcNet     = "/proc/net"
	managedLinuxAcceptPoll  = 5 * time.Millisecond
	managedLinuxUnitPoll    = 50 * time.Millisecond
)

var (
	errManagedLinuxGatewayNotRunning = errors.New("managed gateway service is not running")
	errManagedLinuxGatewayChanged    = errors.New("managed gateway service changed during peer verification")
)

// managedLinuxGatewayUnit is the running gateway unit: its main PID and the
// UID systemd runs it as.
type managedLinuxGatewayUnit struct{ pid, uid int }

// verifyManagedConnectedPeer binds the accepted TCP tuple to the UID of the
// running, packaged systemd gateway. The service account is dedicated to
// DefenseClaw; a different local account cannot create a socket with its UID.
// A Secure Client TCP gateway is not installed on Linux.
//
// Everything comes from PID 1 and root-owned files, never from the service
// process: its /proc/<pid>/exe needs ptrace access and, with /proc mounted
// hidepid, its /proc/<pid>/status is unreadable too, so an ordinary user's
// ACP guard or hook could not read them and refused every verified gateway
// (GAP-1138). The executable is the unit's ExecStart, the UID is the one
// systemd runs the unit as (its User= from the account database when systemd
// does not report it).
//
// The check waits, within the request deadline, for a socket-activated
// gateway to start and accept; the connection carries no HTTP bytes until it
// returns. A restart during the check verifies the new process again.
func verifyManagedConnectedPeer(parent context.Context, client, server *net.TCPAddr, serviceName string) error {
	if serviceName != managedLinuxGatewayService || client == nil || server == nil ||
		!client.IP.IsLoopback() || !server.IP.IsLoopback() {
		return errors.New("managed gateway service or connected endpoint is untrusted")
	}
	ctx, cancel := context.WithTimeout(parent, managedLinuxPeerWait)
	defer cancel()
	for {
		err := verifyManagedLinuxPeerOnce(ctx, client, server)
		if !errors.Is(err, errManagedLinuxGatewayNotRunning) && !errors.Is(err, errManagedLinuxGatewayChanged) {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(managedLinuxUnitPoll):
		}
	}
}

func verifyManagedLinuxPeerOnce(ctx context.Context, client, server *net.TCPAddr) error {
	unit, err := readManagedLinuxGatewayUnit(ctx)
	if err != nil {
		return err
	}
	if err := awaitManagedServiceSocket(ctx, client, server, unit.uid); err != nil {
		return err
	}
	again, err := readManagedLinuxGatewayUnit(ctx)
	if err != nil {
		if errors.Is(err, errManagedLinuxGatewayNotRunning) {
			return errManagedLinuxGatewayChanged
		}
		return err
	}
	if again != unit {
		return errManagedLinuxGatewayChanged
	}
	return nil
}

// awaitManagedServiceSocket waits for the gateway to accept this connection.
// connect() returns once the kernel completes the handshake, before the
// gateway calls accept(); until then /proc/net/tcp reports the server socket
// as root (no owning file, or systemd's activated listener). Root is never
// taken as proof, because an impostor's unaccepted socket reads the same;
// only the service UID is, and any other account refuses at once.
func awaitManagedServiceSocket(ctx context.Context, client, server *net.TCPAddr, serviceUID int) error {
	refused := errors.New("connected gateway socket does not belong to the managed service account")
	for {
		uid, err := findConnectedTCPUID(managedLinuxProcNet, client, server)
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
	return managedLinuxSystemctlShow(ctx).Output()
}

func managedLinuxSystemctlShow(ctx context.Context) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "/usr/bin/systemctl", "--system", "show",
		"--property=MainPID", "--property=ExecStart", "--property=User", "--property=UID",
		managedLinuxGatewayService)
	cmd.Env = trustedSystemctlEnv()
	return cmd
}

// readManagedLinuxGatewayUnit returns the main PID and service UID of the
// gateway unit when that unit starts the packaged gateway executable as a
// non-root account.
func readManagedLinuxGatewayUnit(ctx context.Context) (managedLinuxGatewayUnit, error) {
	output, err := managedLinuxServiceShow(ctx)
	if err != nil {
		return managedLinuxGatewayUnit{}, fmt.Errorf("inspect protected gateway service: %w", err)
	}
	pid, executable, account, runtimeUID := 0, "", "", ""
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
		case "User":
			account = value
		case "UID":
			runtimeUID = value
		}
	}
	if executable != managedLinuxGatewayExecutable {
		return managedLinuxGatewayUnit{}, errors.New("managed gateway service executable is unverified")
	}
	uid, err := managedLinuxServiceUID(account, runtimeUID)
	if err != nil {
		return managedLinuxGatewayUnit{}, err
	}
	if pid < 1 {
		return managedLinuxGatewayUnit{}, errManagedLinuxGatewayNotRunning
	}
	return managedLinuxGatewayUnit{pid: pid, uid: uid}, nil
}

// managedLinuxServiceUID is the UID systemd runs the unit as: the UID it
// reports for the running unit, or else the unit's User= (a name from the
// account database, or a number). A unit without User= runs as root, and
// root never proves the service account.
func managedLinuxServiceUID(account, runtimeUID string) (int, error) {
	unavailable := errors.New("managed gateway service account is unavailable")
	if account == "" {
		return -1, unavailable
	}
	uid, err := strconv.ParseUint(runtimeUID, 10, 32)
	if err != nil {
		uid, err = strconv.ParseUint(account, 10, 32)
	}
	if err != nil {
		entry, lookupErr := managedLinuxLookupUser(account)
		if lookupErr != nil {
			return -1, fmt.Errorf("%w: %v", unavailable, lookupErr)
		}
		uid, err = strconv.ParseUint(entry.Uid, 10, 32)
	}
	// 4294967295 is the kernel's invalid UID.
	if err != nil || uid == 0 || uid == math.MaxUint32 {
		return -1, unavailable
	}
	return int(uid), nil
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
