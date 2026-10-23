// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package hookexec

import (
	"bytes"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func managedClientTestServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var received atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	return server, &received
}

func managedClientPost(client *http.Client, url string) error {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBufferString(`{"target":"/private/scan"}`))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer managed-admin-token")
	resp, err := client.Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}
	return err
}

// GAP-0962: while the managed gateway restarts another account can bind its
// port. The managed client proves the connected socket belongs to root or the
// gateway service account before it writes the bearer or the request.
func TestManagedGatewayClientSendsNothingToAnotherAccountsListener(t *testing.T) {
	server, received := managedClientTestServer(t)
	previous := managedConnectedSocketOwner
	t.Cleanup(func() { managedConnectedSocketOwner = previous })
	const serviceUID = 4243
	client, err := NewManagedGatewayHTTPClient(2*time.Second, server.Listener.Addr().String(), ManagedGatewayPeer{ServiceUID: serviceUID})
	if err != nil {
		t.Fatal(err)
	}
	for _, owner := range []int{4242, 501, 65534} {
		managedConnectedSocketOwner = func(_, _ *net.TCPAddr) (int, error) { return owner, nil }
		if err := managedClientPost(client, server.URL); !errors.Is(err, errManagedGatewayPortHeld) || received.Load() != 0 {
			t.Fatalf("listener of uid %d received %d requests; error = %v", owner, received.Load(), err)
		}
	}
	managedConnectedSocketOwner = func(_, _ *net.TCPAddr) (int, error) { return -1, errors.New("not in the table") }
	if err := managedClientPost(client, server.URL); !errors.Is(err, errManagedGatewayPeerUnverified) || received.Load() != 0 {
		t.Fatalf("an unreadable owner let %d requests through; error = %v", received.Load(), err)
	}
	for i, owner := range []int{serviceUID, 0} {
		managedConnectedSocketOwner = func(_, _ *net.TCPAddr) (int, error) { return owner, nil }
		if err := managedClientPost(client, server.URL); err != nil || received.Load() != int32(i+1) {
			t.Fatalf("listener of uid %d: %d requests, error %v", owner, received.Load(), err)
		}
	}
	// Without a known service account only root is trusted.
	rootOnly, err := NewManagedGatewayHTTPClient(2*time.Second, server.Listener.Addr().String(), ManagedGatewayPeer{ServiceUID: -1})
	if err != nil {
		t.Fatal(err)
	}
	managedConnectedSocketOwner = func(_, _ *net.TCPAddr) (int, error) { return serviceUID, nil }
	if err := managedClientPost(rootOnly, server.URL); !errors.Is(err, errManagedGatewayPortHeld) || received.Load() != 2 {
		t.Fatalf("root-only client accepted uid %d: %d requests, error %v", serviceUID, received.Load(), err)
	}
}

// The kernel's own record of the connected socket decides, on Linux
// (/proc/net/tcp) and macOS (net.inet.tcp.pcblist_n).
func TestManagedGatewayClientReadsTheConnectedSocketOwnerFromTheKernel(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root owns every listener this test can open")
	}
	server, received := managedClientTestServer(t)
	addr := server.Listener.Addr().String()
	other, err := NewManagedGatewayHTTPClient(2*time.Second, addr, ManagedGatewayPeer{ServiceUID: os.Geteuid() + 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := managedClientPost(other, server.URL); !errors.Is(err, errManagedGatewayPortHeld) || received.Load() != 0 {
		t.Fatalf("another account's listener received %d requests; error = %v", received.Load(), err)
	}
	own, err := NewManagedGatewayHTTPClient(2*time.Second, addr, ManagedGatewayPeer{ServiceUID: os.Geteuid()})
	if err != nil {
		t.Fatal(err)
	}
	if err := managedClientPost(own, server.URL); err != nil || received.Load() != 1 {
		t.Fatalf("the service account's listener: %d requests, error %v", received.Load(), err)
	}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	local, remote := conn.LocalAddr().String(), conn.RemoteAddr().String()
	if err := VerifyManagedConnectedTuple(local, remote, ManagedGatewayPeer{ServiceUID: os.Geteuid()}); err != nil {
		t.Fatalf("the CLI tuple check refused the service account's socket: %v", err)
	}
	if err := VerifyManagedConnectedTuple(local, remote, ManagedGatewayPeer{ServiceUID: -1}); !errors.Is(err, errManagedGatewayPortHeld) {
		t.Fatalf("the CLI tuple check accepted another account's socket: %v", err)
	}
}

// A redirect is never followed, so a verified gateway cannot send the
// request on to an unverified endpoint.
func TestManagedGatewayClientRefusesRedirects(t *testing.T) {
	var elsewhere atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { elsewhere.Add(1) }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	previous := managedConnectedSocketOwner
	t.Cleanup(func() { managedConnectedSocketOwner = previous })
	managedConnectedSocketOwner = func(_, _ *net.TCPAddr) (int, error) { return 0, nil }
	client, err := NewManagedGatewayHTTPClient(2*time.Second, redirect.Listener.Addr().String(), ManagedGatewayPeer{ServiceUID: -1})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Get(redirect.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTemporaryRedirect || elsewhere.Load() != 0 {
		t.Fatalf("redirect status %d, %d requests elsewhere", resp.StatusCode, elsewhere.Load())
	}
}
