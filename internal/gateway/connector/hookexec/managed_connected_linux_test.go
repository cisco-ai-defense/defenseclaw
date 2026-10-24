// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const fakeManagedGatewayPID = 4242

func managedGatewayShow(pid int, executable string) string {
	return fmt.Sprintf("MainPID=%d\nExecStart={ path=%s ; argv[]=%s ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=%d ; code=(null) ; status=0/0 }\n",
		pid, executable, executable, pid)
}

// fakeManagedLinuxHost points the managed peer check at a fake /proc that,
// like the real one seen by an ordinary user, has no readable exe link for
// the service process. It returns the TCP table path and the tuple.
func fakeManagedLinuxHost(t *testing.T, show func() string, serviceUID int) (string, *net.TCPAddr, *net.TCPAddr) {
	t.Helper()
	root := t.TempDir()
	process := filepath.Join(root, fmt.Sprint(fakeManagedGatewayPID))
	if err := os.MkdirAll(process, 0o700); err != nil {
		t.Fatal(err)
	}
	status := fmt.Sprintf("Name:\tdefenseclaw-gat\nUid:\t%d\t%d\t%d\t%d\n", serviceUID, serviceUID, serviceUID, serviceUID)
	if err := os.WriteFile(filepath.Join(process, "status"), []byte(status), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "net"), 0o700); err != nil {
		t.Fatal(err)
	}
	previousShow, previousRoot := managedLinuxServiceShow, managedLinuxProcRoot
	managedLinuxServiceShow = func(context.Context) ([]byte, error) { return []byte(show()), nil }
	managedLinuxProcRoot = root
	t.Cleanup(func() { managedLinuxServiceShow, managedLinuxProcRoot = previousShow, previousRoot })
	client := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 52000}
	server := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 18970}
	return filepath.Join(root, "net", "tcp"), client, server
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

// An ordinary user cannot read /proc/<pid>/exe of the gateway's service
// account. The check used to require it and refused every ACP initialize and
// hook request to a verified gateway on managed Linux (GAP-1138).
func TestManagedLinuxPeerVerifiesTheServiceWithoutPtraceAccess(t *testing.T) {
	const serviceUID = 991
	show := func() string { return managedGatewayShow(fakeManagedGatewayPID, managedLinuxGatewayExecutable) }
	table, client, server := fakeManagedLinuxHost(t, show, serviceUID)
	writeConnectedRow(t, table, client, server, serviceUID)
	if err := verifyManagedConnectedPeer(context.Background(), client, server, managedLinuxGatewayService); err != nil {
		t.Fatalf("verified managed gateway refused: %v", err)
	}
	if err := verifyManagedConnectedPeer(context.Background(), client, server, "other.service"); err == nil {
		t.Fatal("another service name was accepted")
	}
}

// connect() returns before the gateway accepts; the kernel reports that
// socket as root until then. The check waits for the service account and
// never takes root as proof.
func TestManagedLinuxPeerWaitsForTheGatewayToAccept(t *testing.T) {
	const serviceUID = 991
	show := func() string { return managedGatewayShow(fakeManagedGatewayPID, managedLinuxGatewayExecutable) }
	for _, pending := range []int{0, -1} {
		t.Run(fmt.Sprintf("pending row uid %d", pending), func(t *testing.T) {
			table, client, server := fakeManagedLinuxHost(t, show, serviceUID)
			writeConnectedRow(t, table, client, server, pending)
			accepted := make(chan error, 1)
			go func() {
				time.Sleep(40 * time.Millisecond)
				accepted <- replaceConnectedRow(table, client, server, serviceUID)
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
		table, client, server := fakeManagedLinuxHost(t, show, serviceUID)
		writeConnectedRow(t, table, client, server, 0)
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		defer cancel()
		if err := verifyManagedConnectedPeer(ctx, client, server, managedLinuxGatewayService); err == nil {
			t.Fatal("an unaccepted root-reported socket was taken as the service account")
		}
	})
	t.Run("another account refuses at once", func(t *testing.T) {
		table, client, server := fakeManagedLinuxHost(t, show, serviceUID)
		writeConnectedRow(t, table, client, server, serviceUID+1)
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

func TestManagedLinuxPeerRefusesAnotherGatewayUnit(t *testing.T) {
	const serviceUID = 991
	cases := map[string]string{
		"wrapper executable": managedGatewayShow(fakeManagedGatewayPID, "/usr/local/bin/defenseclaw-gateway"),
		"not running":        managedGatewayShow(0, managedLinuxGatewayExecutable),
		"no ExecStart":       fmt.Sprintf("MainPID=%d\n", fakeManagedGatewayPID),
		"two commands": fmt.Sprintf("MainPID=%d\nExecStart={ path=%s ; argv[]=%s } ; { path=/bin/sh ; argv[]=/bin/sh }\n",
			fakeManagedGatewayPID, managedLinuxGatewayExecutable, managedLinuxGatewayExecutable),
	}
	for name, output := range cases {
		t.Run(name, func(t *testing.T) {
			table, client, server := fakeManagedLinuxHost(t, func() string { return output }, serviceUID)
			writeConnectedRow(t, table, client, server, serviceUID)
			if err := verifyManagedConnectedPeer(context.Background(), client, server, managedLinuxGatewayService); err == nil {
				t.Fatal("an unverified gateway unit was accepted")
			}
		})
	}
	t.Run("restarted during the check", func(t *testing.T) {
		var calls atomic.Int32
		show := func() string {
			if calls.Add(1) == 1 {
				return managedGatewayShow(fakeManagedGatewayPID, managedLinuxGatewayExecutable)
			}
			return managedGatewayShow(fakeManagedGatewayPID+1, managedLinuxGatewayExecutable)
		}
		table, client, server := fakeManagedLinuxHost(t, show, serviceUID)
		writeConnectedRow(t, table, client, server, serviceUID)
		if err := verifyManagedConnectedPeer(context.Background(), client, server, managedLinuxGatewayService); err == nil {
			t.Fatal("a gateway that restarted during the check was accepted")
		}
	})
}
