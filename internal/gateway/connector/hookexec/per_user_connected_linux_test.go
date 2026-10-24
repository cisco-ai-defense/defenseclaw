// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestConnectedSocketOwnerUsesTheAcceptedTuple(t *testing.T) {
	client := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 52000}
	server := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 18970}
	serverKey, _, err := procTCPEndpoint(server)
	if err != nil {
		t.Fatal(err)
	}
	clientKey, _, err := procTCPEndpoint(client)
	if err != nil {
		t.Fatal(err)
	}
	netDir := t.TempDir()
	// A new same-account listener on the port must not authorize an old
	// connected socket still owned by another account.
	rows := "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n" +
		fmt.Sprintf("0: %s 00000000:0000 0A 0 0 0 %d 0 100\n", serverKey, os.Geteuid()) +
		fmt.Sprintf("1: %s %s 01 0 0 0 %d 0 101\n", serverKey, clientKey, os.Geteuid()+1)
	if err := os.WriteFile(filepath.Join(netDir, "tcp"), []byte(rows), 0o600); err != nil {
		t.Fatal(err)
	}
	uid, err := findConnectedTCPUID(netDir, client, server)
	if err != nil || uid != os.Geteuid()+1 {
		t.Fatalf("accepted socket uid = %d, error=%v; want peer account", uid, err)
	}
	other := &net.TCPAddr{IP: client.IP, Port: client.Port + 1}
	if _, err := findConnectedTCPUID(netDir, other, server); err == nil {
		t.Fatal("a different client tuple was accepted as proof")
	}
}

// GAP-1087: a local service DefenseClaw does not run (the bundled stack's
// collector) is proven when this account or root (Docker's port proxy) holds
// the accepted socket; any other account's socket is refused.
func TestLocalPeerIsThisAccountOrRoot(t *testing.T) {
	client := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 52010}
	server := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4317}
	serverKey, _, err := procTCPEndpoint(server)
	if err != nil {
		t.Fatal(err)
	}
	clientKey, _, err := procTCPEndpoint(client)
	if err != nil {
		t.Fatal(err)
	}
	other := os.Geteuid() + 1
	if os.Geteuid() == 0 {
		other = 1000
	}
	for _, tc := range []struct {
		uid  int
		want bool
	}{{os.Geteuid(), true}, {0, true}, {other, false}} {
		netDir := t.TempDir()
		rows := "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n" +
			fmt.Sprintf("1: %s %s 01 0 0 0 %d 0 101\n", serverKey, clientKey, tc.uid)
		if err := os.WriteFile(filepath.Join(netDir, "tcp"), []byte(rows), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := verifyLocalPeerIn(netDir, client, server); (err == nil) != tc.want {
			t.Fatalf("listener uid %d: error = %v, want accepted %v", tc.uid, err, tc.want)
		}
	}
	if err := verifyLocalPeerIn(t.TempDir(), client, server); err == nil {
		t.Fatal("a socket whose owner cannot be read was accepted")
	}
}
