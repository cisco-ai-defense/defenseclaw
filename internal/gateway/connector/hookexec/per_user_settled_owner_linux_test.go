// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// procRowsSequence serves one accepted-tuple row per read, repeating the
// last, so a test can replay what procfs shows while the gateway accepts.
func procRowsSequence(t *testing.T, client, server *net.TCPAddr, rows ...[2]int) func() (int, error) {
	t.Helper()
	serverKey, _, err := procTCPEndpoint(server)
	if err != nil {
		t.Fatal(err)
	}
	clientKey, _, err := procTCPEndpoint(client)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	reads := 0
	return func() (int, error) {
		row := rows[min(reads, len(rows)-1)]
		reads++
		data := "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n" +
			fmt.Sprintf("1: %s %s 01 0 0 0 %d 0 %d\n", serverKey, clientKey, row[0], row[1])
		if err := os.WriteFile(filepath.Join(dir, "tcp"), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		return findConnectedTCPUID(dir, client, server)
	}
}

// GAP-1435: before accept() the kernel can show UID 0 (and inode 0) for the
// exact accepted tuple. A root per-user hook must not take that 0 as its
// own gateway and send the bearer to the account that then accepts.
func TestPerUserLinuxProvisionalUIDIsNeverProof(t *testing.T) {
	client := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 52011}
	server := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 18970}
	const foreign = 4242
	for _, tc := range []struct {
		name      string
		self      int
		rows      [][2]int // uid, inode per read
		wantErr   string
		wantReads int
	}{
		{name: "root caller, provisional root then foreign listener", self: 0,
			rows: [][2]int{{0, 0}, {0, 0}, {foreign, 77}}, wantErr: "another account", wantReads: 3},
		{name: "root caller, provisional root then root listener", self: 0,
			rows: [][2]int{{0, 0}, {0, 77}}, wantReads: 2},
		{name: "root caller, never accepted", self: 0,
			rows: [][2]int{{0, 0}}, wantErr: "not accepted"},
		{name: "user caller, provisional root then own listener", self: 1001,
			rows: [][2]int{{0, 0}, {1001, 77}}, wantReads: 2},
		{name: "user caller, own uid before accept is not yet proof", self: 1001,
			rows: [][2]int{{1001, 0}, {1001, 0}, {1001, 77}}, wantReads: 3},
		{name: "user caller, provisional root then foreign listener", self: 1001,
			rows: [][2]int{{0, 0}, {foreign, 77}}, wantErr: "another account", wantReads: 2},
		{name: "user caller, accepted root listener", self: 1001,
			rows: [][2]int{{0, 77}}, wantErr: "another account", wantReads: 1},
		{name: "user caller, never accepted", self: 1001,
			rows: [][2]int{{0, 0}}, wantErr: "not accepted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			read := procRowsSequence(t, client, server, tc.rows...)
			reads := 0
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			err := awaitPerUserLinuxSocket(ctx, tc.self, func() (int, error) {
				reads++
				return read()
			})
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("settled owner refused: reads=%d err=%v", reads, err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("unsettled or foreign owner accepted: reads=%d err=%v, want %q", reads, err, tc.wantErr)
			}
			if tc.wantReads != 0 && reads != tc.wantReads {
				t.Fatalf("reads = %d, want %d", reads, tc.wantReads)
			}
		})
	}
}

// The local-stack check accepts this account or the system account, so a
// provisional UID 0 before accept must not count as the system account.
func TestLocalPeerWaitsForTheAcceptedOwner(t *testing.T) {
	client := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 52012}
	server := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 3000}
	other := os.Geteuid() + 1
	if os.Geteuid() == 0 {
		other = 1000
	}
	for _, tc := range []struct {
		name string
		rows [][2]int
		want bool
	}{
		{"provisional root then another account", [][2]int{{0, 0}, {other, 9}}, false},
		{"provisional root then system account", [][2]int{{0, 0}, {0, 9}}, true},
		{"provisional root then this account", [][2]int{{0, 0}, {os.Geteuid(), 9}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			read := procRowsSequence(t, client, server, tc.rows...)
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			self := os.Geteuid()
			err := awaitPerUserLinuxSocket(ctx, self, func() (int, error) {
				uid, err := read()
				if err == nil && uid == 0 {
					return self, nil
				}
				return uid, err
			})
			if (err == nil) != tc.want {
				t.Fatalf("error = %v, want accepted %v", err, tc.want)
			}
		})
	}
}

// A real listener that has not accepted yet: the held connection is not
// proof until accept() settles its owner, then it is.
func TestPerUserLinuxRealConnectionWaitsForAccept(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	conn, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var acceptCalled atomic.Int64
	go func() {
		time.Sleep(250 * time.Millisecond)
		acceptCalled.Store(time.Now().UnixNano())
		server, err := listener.Accept()
		if err == nil {
			defer server.Close()
			time.Sleep(2 * time.Second)
		}
	}()
	err = verifyPerUserConnectedTuple(conn.LocalAddr().(*net.TCPAddr), conn.RemoteAddr().(*net.TCPAddr))
	done := time.Now().UnixNano()
	if err != nil {
		t.Fatalf("same-account accepted connection refused: %v", err)
	}
	if at := acceptCalled.Load(); at == 0 || done < at {
		t.Fatalf("connection was taken as proof before the listener accepted it (accepted=%d done=%d)", at, done)
	}
}

// localhost and ::1 spellings reach a same-account gateway through the
// normalised endpoints (GAP-1135 class, shared with the shell preflight).
func TestPerUserLinuxPostsToEveryLoopbackSpelling(t *testing.T) {
	serve := func(t *testing.T, network, address string) int {
		t.Helper()
		listener, err := net.Listen(network, address)
		if err != nil {
			t.Skipf("%s listener unavailable: %v", address, err)
		}
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"action":"allow"}`))
		}))
		_ = server.Listener.Close()
		server.Listener = listener
		server.Start()
		t.Cleanup(server.Close)
		return listener.Addr().(*net.TCPAddr).Port
	}
	for _, tc := range []struct{ name, network, listen, host string }{
		{"localhost to IPv4 gateway", "tcp4", "127.0.0.1:0", "localhost"},
		{"localhost to IPv6-only gateway", "tcp6", "[::1]:0", "localhost"},
		{"bracketed ::1", "tcp6", "[::1]:0", "[::1]"},
		{"expanded ::1", "tcp6", "[::1]:0", "[0:0:0:0:0:0:0:1]"},
		{"IPv4-mapped loopback", "tcp4", "127.0.0.1:0", "[::ffff:127.0.0.1]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			port := serve(t, tc.network, tc.listen)
			addr := fmt.Sprintf("%s:%d", tc.host, port)
			reply, err := PostPerUserHook(context.Background(), addr, "/api/v1/opencode/hook", nil, []byte(`{"tool_input":"ordinary edit"}`))
			if err != nil || reply.Status != http.StatusOK {
				t.Fatalf("same-account POST to %s: reply=%+v err=%v", addr, reply, err)
			}
		})
	}
	if _, err := PostPerUserHook(context.Background(), "gateway.local:18970", "/api/v1/opencode/hook", nil, nil); err == nil {
		t.Fatalf("non-loopback host was accepted: %v", err)
	}
}
