// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookexec

import (
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

var managedTransportTestMu sync.Mutex

func TestManagedEnterpriseTransportRejectsForeignListenerBeforeHTTPBytes(t *testing.T) {
	managedTransportTestMu.Lock()
	defer managedTransportTestMu.Unlock()

	listener := listenManagedTransportTest(t)
	defer listener.Close()
	bytesRead := acceptManagedTransportBytes(t, listener)
	restoreManagedTransportSeams(t,
		func(string) (uint32, error) { return 101, nil },
		func(net.Conn) (uint32, error) { return 202, nil },
	)

	client, err := managedEnterpriseHTTPClient(time.Second, listener.Addr().String(), "DefenseClawGateway")
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Post(
		"http://"+listener.Addr().String()+"/api/v1/hook",
		"application/json",
		strings.NewReader(`{"secret":"must-not-leak"}`),
	)
	if err == nil || !strings.Contains(err.Error(), errManagedGatewayPeerUnverified.Error()) {
		t.Fatalf("foreign listener error = %v", err)
	}
	if got := <-bytesRead; len(got) != 0 {
		t.Fatalf("foreign listener received %d request bytes: %q", len(got), got)
	}
}

func TestManagedEnterpriseTransportRejectsServicePIDChangeBeforeHTTPBytes(t *testing.T) {
	managedTransportTestMu.Lock()
	defer managedTransportTestMu.Unlock()

	listener := listenManagedTransportTest(t)
	defer listener.Close()
	bytesRead := acceptManagedTransportBytes(t, listener)
	queries := 0
	restoreManagedTransportSeams(t,
		func(string) (uint32, error) {
			queries++
			if queries == 1 {
				return 303, nil
			}
			return 304, nil
		},
		func(net.Conn) (uint32, error) { return 303, nil },
	)

	client, err := managedEnterpriseHTTPClient(time.Second, listener.Addr().String(), "DefenseClawGateway")
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Post(
		"http://"+listener.Addr().String()+"/api/v1/hook",
		"application/json",
		strings.NewReader(`{"secret":"must-not-leak"}`),
	)
	if err == nil || !strings.Contains(err.Error(), errManagedGatewayPeerUnverified.Error()) {
		t.Fatalf("changed service PID error = %v", err)
	}
	if got := <-bytesRead; len(got) != 0 {
		t.Fatalf("PID-race listener received %d request bytes: %q", len(got), got)
	}
}

func TestManagedEnterpriseTransportAllowsStableSCMOwnedListener(t *testing.T) {
	managedTransportTestMu.Lock()
	defer managedTransportTestMu.Unlock()

	listener := listenManagedTransportTest(t)
	defer listener.Close()
	served := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			served <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		buffer := make([]byte, 4096)
		n, err := conn.Read(buffer)
		if err != nil {
			served <- err
			return
		}
		if !strings.Contains(string(buffer[:n]), "POST /api/v1/hook HTTP/1.1") {
			served <- &managedTransportTestError{"unexpected HTTP request"}
			return
		}
		_, err = io.WriteString(
			conn,
			"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 18\r\nConnection: close\r\n\r\n{\"action\":\"allow\"}",
		)
		served <- err
	}()
	restoreManagedTransportSeams(t,
		func(string) (uint32, error) { return 404, nil },
		func(net.Conn) (uint32, error) { return 404, nil },
	)

	client, err := managedEnterpriseHTTPClient(time.Second, listener.Addr().String(), "DefenseClawGateway")
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Post(
		"http://"+listener.Addr().String()+"/api/v1/hook",
		"application/json",
		strings.NewReader(`{}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("response status = %d", response.StatusCode)
	}
	if err := <-served; err != nil {
		t.Fatal(err)
	}
}

func TestConnectedManagedGatewayPIDUsesReverseTCP4Tuple(t *testing.T) {
	managedTransportTestMu.Lock()
	defer managedTransportTestMu.Unlock()

	listener := listenManagedTransportTest(t)
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	client, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	var pid uint32
	for attempt := 0; attempt < 10; attempt++ {
		pid, err = connectedManagedGatewayPID(client)
		if err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	if want := uint32(os.Getpid()); pid != want {
		t.Fatalf("connected listener PID = %d, want current process %d", pid, want)
	}
}

func TestNormalizeManagedGatewayAddressRequiresCanonicalIPv4Loopback(t *testing.T) {
	for _, value := range []string{
		"localhost:8080",
		"[::1]:8080",
		"[::ffff:127.0.0.1]:8080",
		"127.0.0.2:8080",
		"127.1.2.3:8080",
		"127.0.0.1:08080",
		" 127.0.0.1:8080",
		"127.0.0.1:8080 ",
		"10.0.0.1:8080",
	} {
		if _, err := normalizeManagedGatewayAddress(value); err == nil {
			t.Fatalf("normalizeManagedGatewayAddress(%q) unexpectedly succeeded", value)
		}
	}
	if got, err := normalizeManagedGatewayAddress("127.0.0.1:8080"); err != nil || got != "127.0.0.1:8080" {
		t.Fatalf("canonical loopback = %q, %v", got, err)
	}
}

func listenManagedTransportTest(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return listener
}

func acceptManagedTransportBytes(t *testing.T, listener net.Listener) <-chan []byte {
	t.Helper()
	result := make(chan []byte, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			result <- nil
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buffer := make([]byte, 4096)
		n, _ := conn.Read(buffer)
		result <- append([]byte(nil), buffer[:n]...)
	}()
	return result
}

func restoreManagedTransportSeams(
	t *testing.T,
	query func(string) (uint32, error),
	connected func(net.Conn) (uint32, error),
) {
	t.Helper()
	oldQuery := managedEnterpriseQueryServicePID
	oldConnected := managedEnterpriseConnectedPID
	managedEnterpriseQueryServicePID = query
	managedEnterpriseConnectedPID = connected
	// The seam pointers are process-global. Callers hold
	// managedTransportTestMu across the test body, but t.Cleanup runs AFTER
	// the test's defer-based Unlock, so a naive restore could overwrite the
	// seams a sibling test has already installed. Re-acquire the mutex
	// inside the cleanup so the restore stays inside the same critical
	// section it was set up under.
	t.Cleanup(func() {
		managedTransportTestMu.Lock()
		defer managedTransportTestMu.Unlock()
		managedEnterpriseQueryServicePID = oldQuery
		managedEnterpriseConnectedPID = oldConnected
	})
}

type managedTransportTestError struct {
	message string
}

func (e *managedTransportTestError) Error() string { return e.message }
