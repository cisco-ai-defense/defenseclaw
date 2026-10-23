// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookexec

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// GAP-0962: the managed client used by the CLIs sends nothing unless the
// running gateway service process owns the connected socket.
func TestManagedGatewayClientSendsNothingUnlessTheServiceOwnsTheSocket(t *testing.T) {
	managedTransportTestMu.Lock()
	defer managedTransportTestMu.Unlock()
	var received atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	post := func(client *http.Client) error {
		req, err := http.NewRequest(http.MethodPost, server.URL+"/v1/skill/scan", strings.NewReader(`{"target":"C:\\private"}`))
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
	addr := server.Listener.Addr().String()

	// No such service: the real SCM query fails before any dial.
	client, err := NewManagedGatewayHTTPClient(2*time.Second, addr, ManagedGatewayPeer{ServiceName: "DefenseClawGatewayTestAbsent"})
	if err != nil {
		t.Fatal(err)
	}
	if err := post(client); !errors.Is(err, errManagedGatewayPeerUnverified) || received.Load() != 0 {
		t.Fatalf("an absent service let %d requests through; error = %v", received.Load(), err)
	}

	self := uint32(os.Getpid())
	restoreManagedTransportSeams(t,
		func(string) (uint32, error) { return self + 1, nil },
		connectedManagedGatewayPID,
	)
	client, err = NewManagedGatewayHTTPClient(2*time.Second, addr, ManagedGatewayPeer{ServiceName: "DefenseClawGateway"})
	if err != nil {
		t.Fatal(err)
	}
	// The real owner of the connected socket is this test process, not the
	// service.
	if err := post(client); !errors.Is(err, errManagedGatewayPortHeld) || received.Load() != 0 {
		t.Fatalf("another process's listener received %d requests; error = %v", received.Load(), err)
	}
	restoreManagedTransportSeams(t,
		func(string) (uint32, error) { return self, nil },
		connectedManagedGatewayPID,
	)
	if err := post(client); err != nil || received.Load() != 1 {
		t.Fatalf("the service's own listener: %d requests, error %v", received.Load(), err)
	}

	// The same check for the Python CLI's open connection.
	conn, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	local, remote := conn.LocalAddr().String(), conn.RemoteAddr().String()
	if err := VerifyManagedConnectedTuple(local, remote, ManagedGatewayPeer{ServiceName: "DefenseClawGateway"}); err != nil {
		t.Fatalf("the service's socket was refused: %v", err)
	}
	restoreManagedTransportSeams(t,
		func(string) (uint32, error) { return self + 1, nil },
		connectedManagedGatewayPID,
	)
	if err := VerifyManagedConnectedTuple(local, remote, ManagedGatewayPeer{ServiceName: "DefenseClawGateway"}); !errors.Is(err, errManagedGatewayPortHeld) {
		t.Fatalf("another process's socket was accepted: %v", err)
	}
}

// localhost names the same loopback the service listens on.
func TestManagedGatewayClientAcceptsLocalhost(t *testing.T) {
	if _, err := NewManagedGatewayHTTPClient(time.Second, "localhost:18970", ManagedGatewayPeer{ServiceName: "DefenseClawGateway"}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewManagedGatewayHTTPClient(time.Second, "10.0.0.5:18970", ManagedGatewayPeer{ServiceName: "DefenseClawGateway"}); err == nil {
		t.Fatal("a non-loopback managed gateway address was accepted")
	}
}
