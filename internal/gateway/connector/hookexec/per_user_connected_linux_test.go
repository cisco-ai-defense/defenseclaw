// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
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

// perUserRows writes one /proc/net table atomically: the listener and, when
// uid >= 0, the server side of the connection with the given inode.
func perUserRows(t *testing.T, path, serverKey, clientKey string, uid int, inode uint64) {
	t.Helper()
	rows := "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n" +
		fmt.Sprintf("0: %s 00000000:0000 0A 0 0 0 %d 0 100\n", serverKey, os.Geteuid())
	if uid >= 0 {
		rows += fmt.Sprintf("1: %s %s 01 0 0 0 %d 0 %d\n", serverKey, clientKey, uid, inode)
	}
	next := path + ".next"
	if err := os.WriteFile(next, []byte(rows), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(next, path); err != nil {
		t.Fatal(err)
	}
}

func perUserTestKeys(t *testing.T, client, server *net.TCPAddr) (v4Server, v4Client, mappedServer, mappedClient string) {
	t.Helper()
	serverKeys, err := procTCPEndpointKeys(server)
	if err != nil || len(serverKeys) != 2 {
		t.Fatalf("server keys = %v, %v", serverKeys, err)
	}
	clientKeys, err := procTCPEndpointKeys(client)
	if err != nil || len(clientKeys) != 2 {
		t.Fatalf("client keys = %v, %v", clientKeys, err)
	}
	return serverKeys[0].key, clientKeys[0].key, serverKeys[1].key, clientKeys[1].key
}

// GAP-1121: an IPv4 connection accepted by a dual-stack listener is listed
// in tcp6 with IPv4-mapped endpoints, never in tcp.
func TestConnectedSocketOwnerFindsAnIPv4TupleInTCP6(t *testing.T) {
	client := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 52000}
	server := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 18970}
	v4Server, _, mappedServer, mappedClient := perUserTestKeys(t, client, server)
	if mappedServer != "0000000000000000FFFF00000100007F:4A1A" {
		t.Fatalf("mapped server key = %s", mappedServer)
	}
	self := os.Geteuid()
	other := self + 1

	t.Run("same account in tcp6", func(t *testing.T) {
		netDir := t.TempDir()
		perUserRows(t, filepath.Join(netDir, "tcp"), v4Server, "", -1, 0)
		perUserRows(t, filepath.Join(netDir, "tcp6"), mappedServer, mappedClient, self, 101)
		if err := awaitPerUserLinuxSocket(context.Background(), netDir, client, server, self); err != nil {
			t.Fatalf("same-account dual-stack gateway refused: %v", err)
		}
		// A mapped endpoint reported by the Python CLI is the same tuple.
		mapped := &net.TCPAddr{IP: net.ParseIP("::ffff:127.0.0.1"), Port: client.Port}
		if err := awaitPerUserLinuxSocket(context.Background(), netDir, mapped, server, self); err != nil {
			t.Fatalf("IPv4-mapped client endpoint refused: %v", err)
		}
	})
	t.Run("other account in tcp6", func(t *testing.T) {
		netDir := t.TempDir()
		perUserRows(t, filepath.Join(netDir, "tcp"), v4Server, "", -1, 0)
		perUserRows(t, filepath.Join(netDir, "tcp6"), mappedServer, mappedClient, other, 101)
		if err := awaitPerUserLinuxSocket(context.Background(), netDir, client, server, self); !errors.Is(err, errPerUserForeignSocket) {
			t.Fatalf("foreign dual-stack gateway: error = %v, want refusal", err)
		}
	})
	t.Run("listed twice", func(t *testing.T) {
		netDir := t.TempDir()
		_, v4Client, _, _ := perUserTestKeys(t, client, server)
		perUserRows(t, filepath.Join(netDir, "tcp"), v4Server, v4Client, self, 101)
		perUserRows(t, filepath.Join(netDir, "tcp6"), mappedServer, mappedClient, other, 102)
		if _, err := findConnectedTCPSocket(netDir, client, server); err == nil {
			t.Fatal("an ambiguous tuple was accepted as proof")
		}
	})
	t.Run("no tcp6 table", func(t *testing.T) {
		netDir := t.TempDir()
		_, v4Client, _, _ := perUserTestKeys(t, client, server)
		perUserRows(t, filepath.Join(netDir, "tcp"), v4Server, v4Client, self, 101)
		if err := awaitPerUserLinuxSocket(context.Background(), netDir, client, server, self); err != nil {
			t.Fatalf("IPv4-only host refused: %v", err)
		}
	})
	t.Run("no tcp table", func(t *testing.T) {
		netDir := t.TempDir()
		perUserRows(t, filepath.Join(netDir, "tcp6"), mappedServer, mappedClient, self, 101)
		if _, err := findConnectedTCPSocket(netDir, client, server); err == nil {
			t.Fatal("an unreadable IPv4 table was skipped")
		}
	})
	t.Run("IPv6 tuple stays in tcp6 only", func(t *testing.T) {
		v6Client := &net.TCPAddr{IP: net.IPv6loopback, Port: 52000}
		v6Server := &net.TCPAddr{IP: net.IPv6loopback, Port: 18970}
		serverKey, _, _ := procTCPEndpoint(v6Server)
		clientKey, _, _ := procTCPEndpoint(v6Client)
		netDir := t.TempDir()
		perUserRows(t, filepath.Join(netDir, "tcp6"), serverKey, clientKey, self, 101)
		if err := awaitPerUserLinuxSocket(context.Background(), netDir, v6Client, v6Server, self); err != nil {
			t.Fatalf("IPv6 gateway refused: %v", err)
		}
		if _, err := findConnectedTCPSocket(netDir, client, v6Server); err == nil {
			t.Fatal("mixed address families were accepted")
		}
	})
}

// GAP-1121: connect() returns before the gateway accepts. Until then the
// server row has no inode and kernels that read the owner from it report
// root, and the row can be missing for a moment. The hook waits on the same
// connection; it never takes root, a missing row or a timeout as proof.
func TestPerUserSocketWaitsForTheGatewayToAccept(t *testing.T) {
	client := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 52000}
	server := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 18970}
	v4Server, v4Client, _, _ := perUserTestKeys(t, client, server)
	restore := perUserLinuxAcceptPoll
	perUserLinuxAcceptPoll = time.Millisecond
	t.Cleanup(func() { perUserLinuxAcceptPoll = restore })
	self := os.Geteuid()
	if self == 0 {
		self = 1000 // the account under test; rows are synthetic
	}

	for _, tc := range []struct {
		name               string
		firstUID, finalUID int
		firstInode         uint64
		want               error
	}{
		{name: "provisional root row, then accepted", firstUID: 0, firstInode: 0, finalUID: self},
		{name: "missing row, then accepted", firstUID: -1, finalUID: self},
		{name: "listener account before accept", firstUID: self, firstInode: 0, finalUID: self},
		{name: "provisional root row, then another account", firstUID: 0, firstInode: 0, finalUID: self + 1, want: errPerUserForeignSocket},
	} {
		t.Run(tc.name, func(t *testing.T) {
			table := filepath.Join(t.TempDir(), "tcp")
			perUserRows(t, table, v4Server, v4Client, tc.firstUID, tc.firstInode)
			done := make(chan struct{})
			go func() {
				defer close(done)
				time.Sleep(40 * time.Millisecond)
				perUserRows(t, table, v4Server, v4Client, tc.finalUID, 101)
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err := awaitPerUserLinuxSocket(ctx, filepath.Dir(table), client, server, self)
			<-done
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}

	for _, tc := range []struct {
		name    string
		uid     int
		inode   uint64
		account int
		want    error
	}{
		{name: "never accepted", uid: 0, inode: 0, account: self, want: errPerUserSocketUnaccepted},
		{name: "never listed", uid: -1, account: self, want: errConnectedSocketNotFound},
		{name: "root account, never accepted", uid: 0, inode: 0, account: 0, want: errPerUserSocketUnaccepted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			table := filepath.Join(t.TempDir(), "tcp")
			perUserRows(t, table, v4Server, v4Client, tc.uid, tc.inode)
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
			defer cancel()
			if err := awaitPerUserLinuxSocket(ctx, filepath.Dir(table), client, server, tc.account); !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}

	// A row another account owns refuses at once, accepted or not, without
	// waiting out the deadline.
	for _, inode := range []uint64{0, 101} {
		table := filepath.Join(t.TempDir(), "tcp")
		perUserRows(t, table, v4Server, v4Client, self+1, inode)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		started := time.Now()
		err := awaitPerUserLinuxSocket(ctx, filepath.Dir(table), client, server, self)
		cancel()
		if !errors.Is(err, errPerUserForeignSocket) || time.Since(started) > 2*time.Second {
			t.Fatalf("inode %d: error = %v after %s, want an immediate refusal", inode, err, time.Since(started))
		}
	}
	// The root account is proven only by an accepted row.
	table := filepath.Join(t.TempDir(), "tcp")
	perUserRows(t, table, v4Server, v4Client, 0, 101)
	if err := awaitPerUserLinuxSocket(context.Background(), filepath.Dir(table), client, server, 0); err != nil {
		t.Fatalf("root account's accepted row: %v", err)
	}
}

// GAP-1121 end to end on the real kernel tables: a healthy same-account
// gateway on a dual-stack listener, asked over IPv4, answers, also when it
// accepts the connection late.
func TestPerUserClientReachesARealSameAccountGateway(t *testing.T) {
	for _, tc := range []struct {
		name, listen string
		acceptDelay  time.Duration
	}{
		{name: "IPv4 listener", listen: "127.0.0.1:0"},
		{name: "IPv4 listener, late accept", listen: "127.0.0.1:0", acceptDelay: 150 * time.Millisecond},
		{name: "dual-stack listener", listen: "[::]:0"},
		{name: "dual-stack listener, late accept", listen: "[::]:0", acceptDelay: 150 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", tc.listen)
			if err != nil {
				t.Skipf("listen %s: %v", tc.listen, err)
			}
			if tc.listen == "[::]:0" {
				if _, statErr := os.Stat("/proc/self/net/tcp6"); statErr != nil {
					listener.Close()
					t.Skip("no IPv6 on this host")
				}
			}
			delayed := &delayedAcceptListener{Listener: listener, delay: tc.acceptDelay}
			server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"action":"allow"}`))
			}), ReadHeaderTimeout: 5 * time.Second}
			go func() { _ = server.Serve(delayed) }()
			t.Cleanup(func() { _ = server.Close() })
			port := listener.Addr().(*net.TCPAddr).Port
			apiAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
			client, err := NewPerUserGatewayHTTPClient(10*time.Second, apiAddr)
			if err != nil {
				t.Fatal(err)
			}
			response, err := client.Get("http://" + apiAddr + "/health")
			if err != nil {
				t.Fatalf("same-account gateway refused: %v", err)
			}
			response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Fatalf("status = %d", response.StatusCode)
			}
		})
	}
}

type delayedAcceptListener struct {
	net.Listener
	delay time.Duration
}

func (l *delayedAcceptListener) Accept() (net.Conn, error) {
	if l.delay > 0 {
		time.Sleep(l.delay)
	}
	return l.Listener.Accept()
}
