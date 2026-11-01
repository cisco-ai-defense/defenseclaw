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
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
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

func TestConnectedSocketOwnerFindsIPv4AcceptedByDualStackListener(t *testing.T) {
	client := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 52000}
	server := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 18970}
	netDir := t.TempDir()
	// An IPv4 client of an IPv6 dual-stack listener has no server row in
	// tcp. The exact accepted reverse tuple is IPv4-mapped in tcp6.
	if err := os.WriteFile(filepath.Join(netDir, "tcp"), []byte("sl local_address rem_address st uid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rows := "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n" +
		fmt.Sprintf("0: 0000000000000000FFFF00000100007F:4A1A 0000000000000000FFFF00000100007F:CB20 01 0 0 0 %d 0 100\n", os.Geteuid())
	if err := os.WriteFile(filepath.Join(netDir, "tcp6"), []byte(rows), 0o600); err != nil {
		t.Fatal(err)
	}
	uid, err := findConnectedTCPUID(netDir, client, server)
	if err != nil || uid != os.Geteuid() {
		t.Fatalf("dual-stack accepted socket uid = %d, error=%v; want %d", uid, err, os.Geteuid())
	}
}

func TestPerUserLinuxWaitsOnlyForMissingAcceptedTuple(t *testing.T) {
	self := os.Geteuid()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	reads := 0
	err := awaitPerUserLinuxSocket(ctx, self, func() (int, error) {
		reads++
		if reads < 3 {
			return -1, errConnectedSocketNotFound
		}
		return self, nil
	})
	if err != nil || reads != 3 {
		t.Fatalf("same-account accepted row after connect: reads=%d err=%v", reads, err)
	}
	t.Run("unaccepted row becomes same account", func(t *testing.T) {
		reads := 0
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		err := awaitPerUserLinuxSocket(ctx, self, func() (int, error) {
			reads++
			if reads < 3 {
				return -1, errConnectedSocketNotAccepted
			}
			return self, nil
		})
		if err != nil || reads != 3 {
			t.Fatalf("provisional kernel row changed to peer owner: reads=%d err=%v", reads, err)
		}
	})
	t.Run("persistent unaccepted row stays refused", func(t *testing.T) {
		reads := 0
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
		defer cancel()
		err := awaitPerUserLinuxSocket(ctx, self, func() (int, error) {
			reads++
			return -1, errConnectedSocketNotAccepted
		})
		if !errors.Is(err, errConnectedSocketNotAccepted) || reads < 2 {
			t.Fatalf("unaccepted owner was accepted or not rechecked: reads=%d err=%v", reads, err)
		}
	})
	for _, tc := range []struct {
		name    string
		inspect func() (int, error)
	}{
		{"foreign owner", func() (int, error) { return self + 1, nil }},
		{"accepted root owner", func() (int, error) {
			if self == 0 {
				return 4242, nil
			}
			return 0, nil
		}},
		{"table read error", func() (int, error) { return -1, errors.New("table unreadable") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reads := 0
			err := awaitPerUserLinuxSocket(context.Background(), self, func() (int, error) {
				reads++
				return tc.inspect()
			})
			if err == nil || reads != 1 {
				t.Fatalf("unverified peer retried or allowed: reads=%d err=%v", reads, err)
			}
		})
	}
	short, stop := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer stop()
	if err := awaitPerUserLinuxSocket(short, self, func() (int, error) {
		return -1, errConnectedSocketNotFound
	}); !errors.Is(err, errConnectedSocketNotFound) {
		t.Fatalf("absent tuple was accepted after retry budget: %v", err)
	}
}

func TestPerUserLinuxPostsToSameAccountDualStackListener(t *testing.T) {
	listener, err := net.Listen("tcp", "[::]:0")
	if err != nil {
		t.Skipf("dual-stack listener unavailable: %v", err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"action":"allow"}`))
	}))
	_ = server.Listener.Close()
	server.Listener = listener
	server.Start()
	defer server.Close()
	addr := fmt.Sprintf("127.0.0.1:%d", listener.Addr().(*net.TCPAddr).Port)
	reply, err := PostPerUserHook(context.Background(), addr, "/api/v1/opencode/hook", nil, []byte(`{"tool_input":"ordinary edit"}`))
	if err != nil || reply.Status != http.StatusOK {
		t.Fatalf("same-account dual-stack POST: reply=%+v err=%v", reply, err)
	}
}

// Under load the TCP handshake can complete before the gateway process
// accepts the socket. The pre-accept row has no gateway owner yet; wait for
// the same connected tuple to acquire the listener's uid before sending.
func TestPerUserPostWaitsForSameAccountAccept(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var received atomic.Int32
	go func() {
		time.Sleep(350 * time.Millisecond)
		_ = http.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			received.Add(1)
			_, _ = w.Write([]byte(`{"action":"allow"}`))
		}))
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	reply, err := PostPerUserHook(ctx, listener.Addr().String(), "/api/v1/claude-code/hook",
		map[string]string{"Authorization": "Bearer example"}, []byte(`{"command":"echo ok"}`))
	if err != nil || reply.Status != http.StatusOK || received.Load() != 1 {
		t.Fatalf("same-account delayed accept: reply=%+v requests=%d error=%v", reply, received.Load(), err)
	}
}
