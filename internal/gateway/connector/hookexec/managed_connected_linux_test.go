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
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	fakeManagedGatewayPID = 4242
	fakeServiceUID        = 991
)

// managedGatewayShow is systemd's answer for the packaged unit while it is
// starting or running: User= from the unit, and no runtime UID reported, so
// the check takes the account database.
func managedGatewayShow(pid int, executable string) string {
	return managedGatewayShowAs(pid, executable, "defenseclaw", "[not set]")
}

func managedGatewayShowAs(pid int, executable, account, runtimeUID string) string {
	return fmt.Sprintf("MainPID=%d\nExecStart={ path=%s ; argv[]=%s ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=%d ; code=(null) ; status=0/0 }\nUser=%s\nUID=%s\n",
		pid, executable, executable, pid, account, runtimeUID)
}

// fakeManagedLinuxHost points the managed peer check at a fake /proc/net and
// account database. Like /proc mounted hidepid=2 seen by an ordinary user,
// the fake has no entry at all for the service process. It returns the TCP
// table path and the tuple.
func fakeManagedLinuxHost(t *testing.T, show func() string) (string, *net.TCPAddr, *net.TCPAddr) {
	t.Helper()
	procNet := filepath.Join(t.TempDir(), "net")
	if err := os.MkdirAll(procNet, 0o700); err != nil {
		t.Fatal(err)
	}
	previousShow, previousNet, previousLookup := managedLinuxServiceShow, managedLinuxProcNet, managedLinuxLookupUser
	managedLinuxServiceShow = func(context.Context) ([]byte, error) { return []byte(show()), nil }
	managedLinuxProcNet = procNet
	managedLinuxLookupUser = func(name string) (*user.User, error) {
		switch name {
		case "defenseclaw":
			return &user.User{Username: name, Uid: strconv.Itoa(fakeServiceUID)}, nil
		case "root":
			return &user.User{Username: name, Uid: "0"}, nil
		}
		return nil, user.UnknownUserError(name)
	}
	t.Cleanup(func() {
		managedLinuxServiceShow, managedLinuxProcNet, managedLinuxLookupUser = previousShow, previousNet, previousLookup
	})
	client := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 52000}
	server := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 18970}
	return filepath.Join(procNet, "tcp"), client, server
}

func writeConnectedRow(t *testing.T, table string, client, server *net.TCPAddr, uid int) {
	t.Helper()
	if err := replaceConnectedRow(table, client, server, uid); err != nil {
		t.Fatal(err)
	}
}

// replaceConnectedRow writes the gateway listener and, for uid >= 0, the
// accepted server socket of the tuple, replacing the table atomically.
func replaceConnectedRow(table string, client, server *net.TCPAddr, uid int) error {
	serverKey, _, _ := procTCPEndpoint(server)
	clientKey, _, _ := procTCPEndpoint(client)
	rows := "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n" +
		fmt.Sprintf("0: %s 00000000:0000 0A 0 0 0 0 0 100\n", serverKey)
	if uid >= 0 {
		rows += fmt.Sprintf("1: %s %s 01 0 0 0 %d 0 101\n", serverKey, clientKey, uid)
	}
	next := table + ".next"
	if err := os.WriteFile(next, []byte(rows), 0o600); err != nil {
		return err
	}
	return os.Rename(next, table)
}

// An ordinary user can read neither /proc/<pid>/exe of the gateway's service
// account (ptrace access) nor, with /proc mounted hidepid=1 or 2, its
// /proc/<pid>/status. The check used to require them and refused every ACP
// initialize and hook request to a verified gateway on managed Linux
// (GAP-1138). The fixture has no /proc entry for the service process at all.
func TestManagedLinuxPeerVerifiesTheServiceWhenProcHidesItsProcess(t *testing.T) {
	show := func() string { return managedGatewayShow(fakeManagedGatewayPID, managedLinuxGatewayExecutable) }
	table, client, server := fakeManagedLinuxHost(t, show)
	writeConnectedRow(t, table, client, server, fakeServiceUID)
	if err := verifyManagedConnectedPeer(context.Background(), client, server, managedLinuxGatewayService); err != nil {
		t.Fatalf("verified managed gateway refused: %v", err)
	}
	if err := verifyManagedConnectedPeer(context.Background(), client, server, "other.service"); err == nil {
		t.Fatal("another service name was accepted")
	}
}

// The service UID comes from PID 1 (the UID it runs the unit as) or from the
// unit's User= and the account database, never from the service process.
// Root never proves the service account.
func TestManagedLinuxPeerTakesTheServiceUIDFromTheUnit(t *testing.T) {
	accepted := map[string]string{
		"runtime UID without an account entry": managedGatewayShowAs(fakeManagedGatewayPID, managedLinuxGatewayExecutable, "dc-dynamic", strconv.Itoa(fakeServiceUID)),
		"account database":                     managedGatewayShowAs(fakeManagedGatewayPID, managedLinuxGatewayExecutable, "defenseclaw", "[not set]"),
		"numeric User=":                        managedGatewayShowAs(fakeManagedGatewayPID, managedLinuxGatewayExecutable, strconv.Itoa(fakeServiceUID), "[not set]"),
		"older systemd without UID": fmt.Sprintf("MainPID=%d\nExecStart={ path=%s ; argv[]=%s }\nUser=defenseclaw\n",
			fakeManagedGatewayPID, managedLinuxGatewayExecutable, managedLinuxGatewayExecutable),
	}
	for name, output := range accepted {
		t.Run(name, func(t *testing.T) {
			table, client, server := fakeManagedLinuxHost(t, func() string { return output })
			writeConnectedRow(t, table, client, server, fakeServiceUID)
			if err := verifyManagedConnectedPeer(context.Background(), client, server, managedLinuxGatewayService); err != nil {
				t.Fatalf("verified managed gateway refused: %v", err)
			}
			writeConnectedRow(t, table, client, server, fakeServiceUID+1)
			if err := verifyManagedConnectedPeer(context.Background(), client, server, managedLinuxGatewayService); err == nil {
				t.Fatal("another account's socket was accepted")
			}
		})
	}
	refused := map[string]string{
		"no User= (root)": managedGatewayShowAs(fakeManagedGatewayPID, managedLinuxGatewayExecutable, "", "0"),
		"runtime UID 0":   managedGatewayShowAs(fakeManagedGatewayPID, managedLinuxGatewayExecutable, "defenseclaw", "0"),
		"invalid UID":     managedGatewayShowAs(fakeManagedGatewayPID, managedLinuxGatewayExecutable, "defenseclaw", "4294967295"),
		"User=root":       managedGatewayShowAs(fakeManagedGatewayPID, managedLinuxGatewayExecutable, "root", "[not set]"),
		"User=0":          managedGatewayShowAs(fakeManagedGatewayPID, managedLinuxGatewayExecutable, "0", "[not set]"),
		"unknown account": managedGatewayShowAs(fakeManagedGatewayPID, managedLinuxGatewayExecutable, "nosuchaccount", "[not set]"),
	}
	for name, output := range refused {
		t.Run(name, func(t *testing.T) {
			table, client, server := fakeManagedLinuxHost(t, func() string { return output })
			// A root-reported socket is the row a root "service account"
			// would match.
			writeConnectedRow(t, table, client, server, 0)
			started := time.Now()
			err := verifyManagedConnectedPeer(context.Background(), client, server, managedLinuxGatewayService)
			if err == nil || !strings.Contains(err.Error(), "service account is unavailable") {
				t.Fatalf("an unverified service account: error = %v", err)
			}
			if elapsed := time.Since(started); elapsed > time.Second {
				t.Fatalf("an unverified service account took %s to refuse", elapsed)
			}
		})
	}
}

// connect() returns before the gateway accepts; the kernel reports that
// socket as root until then. The check waits for the service account and
// never takes root as proof.
func TestManagedLinuxPeerWaitsForTheGatewayToAccept(t *testing.T) {
	show := func() string { return managedGatewayShow(fakeManagedGatewayPID, managedLinuxGatewayExecutable) }
	for _, pending := range []int{0, -1} {
		t.Run(fmt.Sprintf("pending row uid %d", pending), func(t *testing.T) {
			table, client, server := fakeManagedLinuxHost(t, show)
			writeConnectedRow(t, table, client, server, pending)
			accepted := make(chan error, 1)
			go func() {
				time.Sleep(40 * time.Millisecond)
				accepted <- replaceConnectedRow(table, client, server, fakeServiceUID)
			}()
			err := verifyManagedConnectedPeer(context.Background(), client, server, managedLinuxGatewayService)
			if writeErr := <-accepted; writeErr != nil {
				t.Fatal(writeErr)
			}
			if err != nil {
				t.Fatalf("a connection the gateway accepted late was refused: %v", err)
			}
		})
	}
	t.Run("never accepted", func(t *testing.T) {
		table, client, server := fakeManagedLinuxHost(t, show)
		writeConnectedRow(t, table, client, server, 0)
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		defer cancel()
		if err := verifyManagedConnectedPeer(ctx, client, server, managedLinuxGatewayService); err == nil {
			t.Fatal("an unaccepted root-reported socket was taken as the service account")
		}
	})
	t.Run("another account refuses at once", func(t *testing.T) {
		table, client, server := fakeManagedLinuxHost(t, show)
		writeConnectedRow(t, table, client, server, fakeServiceUID+1)
		started := time.Now()
		if err := verifyManagedConnectedPeer(context.Background(), client, server, managedLinuxGatewayService); err == nil ||
			!strings.Contains(err.Error(), "does not belong to the managed service account") {
			t.Fatalf("another account's socket error = %v", err)
		}
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("another account's socket took %s to refuse", elapsed)
		}
	})
}

// Under socket activation PID 1 holds the listener, so connect() succeeds
// while the gateway is still starting (MainPID 0) and the gateway may accept
// well after that. The check used to refuse a MainPID of 0 at once and give
// up on accept after 3 s; it now waits within the request deadline
// (GAP-1138).
func TestManagedLinuxPeerWaitsForASocketActivatedStart(t *testing.T) {
	t.Run("starts, then accepts after 3s", func(t *testing.T) {
		begin := time.Now()
		show := func() string {
			if time.Since(begin) < 1500*time.Millisecond {
				return managedGatewayShow(0, managedLinuxGatewayExecutable)
			}
			return managedGatewayShow(fakeManagedGatewayPID, managedLinuxGatewayExecutable)
		}
		table, client, server := fakeManagedLinuxHost(t, show)
		writeConnectedRow(t, table, client, server, 0)
		accepted := make(chan error, 1)
		go func() {
			time.Sleep(3300 * time.Millisecond)
			accepted <- replaceConnectedRow(table, client, server, fakeServiceUID)
		}()
		err := verifyManagedConnectedPeer(context.Background(), client, server, managedLinuxGatewayService)
		if writeErr := <-accepted; writeErr != nil {
			t.Fatal(writeErr)
		}
		if err != nil {
			t.Fatalf("a socket-activated gateway that started and accepted within the request deadline was refused: %v", err)
		}
	})
	t.Run("never starts: refused at the request deadline", func(t *testing.T) {
		show := func() string { return managedGatewayShow(0, managedLinuxGatewayExecutable) }
		table, client, server := fakeManagedLinuxHost(t, show)
		writeConnectedRow(t, table, client, server, 0)
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		started := time.Now()
		err := verifyManagedConnectedPeer(ctx, client, server, managedLinuxGatewayService)
		if !errors.Is(err, errManagedLinuxGatewayNotRunning) {
			t.Fatalf("a gateway that never started: error = %v", err)
		}
		if elapsed := time.Since(started); elapsed > 2*time.Second {
			t.Fatalf("the check outlived the request deadline: %s", elapsed)
		}
	})
}

func TestManagedLinuxPeerRefusesAnotherGatewayUnit(t *testing.T) {
	cases := map[string]string{
		"wrapper executable":     managedGatewayShow(fakeManagedGatewayPID, "/usr/local/bin/defenseclaw-gateway"),
		"wrapper, not yet began": managedGatewayShow(0, "/usr/local/bin/defenseclaw-gateway"),
		"no ExecStart":           fmt.Sprintf("MainPID=%d\nUser=defenseclaw\n", fakeManagedGatewayPID),
		"two commands": fmt.Sprintf("MainPID=%d\nExecStart={ path=%s ; argv[]=%s } ; { path=/bin/sh ; argv[]=/bin/sh }\nUser=defenseclaw\n",
			fakeManagedGatewayPID, managedLinuxGatewayExecutable, managedLinuxGatewayExecutable),
		"no service account": managedGatewayShowAs(fakeManagedGatewayPID, managedLinuxGatewayExecutable, "", "[not set]"),
	}
	for name, output := range cases {
		t.Run(name, func(t *testing.T) {
			table, client, server := fakeManagedLinuxHost(t, func() string { return output })
			writeConnectedRow(t, table, client, server, fakeServiceUID)
			started := time.Now()
			if err := verifyManagedConnectedPeer(context.Background(), client, server, managedLinuxGatewayService); err == nil {
				t.Fatal("an unverified gateway unit was accepted")
			}
			if elapsed := time.Since(started); elapsed > time.Second {
				t.Fatalf("an unverified unit took %s to refuse; only a start may wait", elapsed)
			}
		})
	}
	t.Run("not running", func(t *testing.T) {
		table, client, server := fakeManagedLinuxHost(t, func() string { return managedGatewayShow(0, managedLinuxGatewayExecutable) })
		writeConnectedRow(t, table, client, server, fakeServiceUID)
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		if err := verifyManagedConnectedPeer(ctx, client, server, managedLinuxGatewayService); err == nil {
			t.Fatal("a gateway unit that is not running was accepted")
		}
	})
	// A restart during the check verifies the new process again; a restart
	// into another unit, or a unit that never holds still, is refused.
	restarts := []struct {
		name   string
		accept bool
		show   func(call int32) string
	}{
		{"restarted during the check", true, func(call int32) string {
			if call == 1 {
				return managedGatewayShow(fakeManagedGatewayPID, managedLinuxGatewayExecutable)
			}
			return managedGatewayShow(fakeManagedGatewayPID+1, managedLinuxGatewayExecutable)
		}},
		{"stopped during the check, then started", true, func(call int32) string {
			switch call {
			case 1:
				return managedGatewayShow(fakeManagedGatewayPID, managedLinuxGatewayExecutable)
			case 2, 3:
				return managedGatewayShow(0, managedLinuxGatewayExecutable)
			}
			return managedGatewayShow(fakeManagedGatewayPID+1, managedLinuxGatewayExecutable)
		}},
		{"restarted into another unit", false, func(call int32) string {
			if call == 1 {
				return managedGatewayShow(fakeManagedGatewayPID, managedLinuxGatewayExecutable)
			}
			return managedGatewayShow(fakeManagedGatewayPID+1, "/usr/local/bin/defenseclaw-gateway")
		}},
		{"restarted under another account", false, func(call int32) string {
			if call == 1 {
				return managedGatewayShow(fakeManagedGatewayPID, managedLinuxGatewayExecutable)
			}
			return managedGatewayShowAs(fakeManagedGatewayPID+1, managedLinuxGatewayExecutable, "defenseclaw", strconv.Itoa(fakeServiceUID+1))
		}},
		{"restarts on every read", false, func(call int32) string {
			return managedGatewayShow(fakeManagedGatewayPID+int(call), managedLinuxGatewayExecutable)
		}},
	}
	for _, tc := range restarts {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			table, client, server := fakeManagedLinuxHost(t, func() string { return tc.show(calls.Add(1)) })
			writeConnectedRow(t, table, client, server, fakeServiceUID)
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			err := verifyManagedConnectedPeer(ctx, client, server, managedLinuxGatewayService)
			if tc.accept && err != nil {
				t.Fatalf("a gateway verified again after its restart was refused: %v", err)
			}
			if !tc.accept && err == nil {
				t.Fatal("an unverified restart was accepted")
			}
		})
	}
}

// The probe runs in the editor's environment. A DBUS_SYSTEM_BUS_ADDRESS (or
// SYSTEMD_*) the editor sets must not reach systemctl, or a healthy gateway
// cannot answer (GAP-1138).
func TestManagedLinuxSystemctlProbeIgnoresTheEditorEnvironment(t *testing.T) {
	deadBus := "unix:path=" + filepath.Join(t.TempDir(), "no-bus")
	baseline, baselineErr := systemctlShowManagedGateway(context.Background())
	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", deadBus)
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", deadBus)
	t.Setenv("SYSTEMD_BUS_TIMEOUT", "1us")
	t.Setenv("SYSTEMD_LOG_LEVEL", "debug")
	for name, cmd := range map[string]*exec.Cmd{
		"peer check":    managedLinuxSystemctlShow(context.Background()),
		"gateway watch": standaloneGatewayServiceCommand(context.Background(), "/usr/bin/systemctl"),
	} {
		if env := cmd.Environ(); !slices.Equal(env, trustedSystemctlEnv()) {
			t.Fatalf("%s systemctl environment = %q, want only %q", name, env, trustedSystemctlEnv())
		}
	}
	if baselineErr != nil || !strings.Contains(string(baseline), "MainPID=") {
		t.Skipf("systemctl --system show is unavailable here (%v); the environment check above still ran", baselineErr)
	}
	output, err := systemctlShowManagedGateway(context.Background())
	if err != nil || !strings.Contains(string(output), "MainPID=") {
		t.Fatalf("an editor bus address broke the systemd probe: %v (%q)", err, output)
	}
}
