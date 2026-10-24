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

func TestLocalPeerAcceptsOnlyThisAccountOrRoot(t *testing.T) {
	client := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 52010}
	server := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 3000}
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
