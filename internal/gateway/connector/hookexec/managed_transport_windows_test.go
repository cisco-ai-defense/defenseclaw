// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookexec

import (
	"errors"
	"fmt"
	"io"
	"math/bits"
	"net"
	"net/http"
	"os"
	"strconv"
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
	if err == nil || !strings.Contains(err.Error(), errManagedGatewayPeerUnverified.Error()) || !errors.Is(err, errManagedGatewayPortHeld) {
		t.Fatalf("foreign listener error = %v, want a peer failure that names the held port (GAP-1029)", err)
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

// GAP-0155: a gateway service that runs but does not listen yet (it is
// starting, or stopping) is tried again at once: the hook reads the listen
// table instead of a connect that Windows answers only after about 2 s.
func TestManagedEnterpriseTransportDoesNotDialAPortNobodyListensOn(t *testing.T) {
	managedTransportTestMu.Lock()
	defer managedTransportTestMu.Unlock()

	listener := listenManagedTransportTest(t)
	addr := listener.Addr().String()
	_ = listener.Close()
	restoreManagedTransportSeams(t,
		func(string) (uint32, error) { return 101, nil },
		func(net.Conn) (uint32, error) { return 101, nil },
	)
	client, err := managedEnterpriseHTTPClient(5*time.Second, addr, "DefenseClawGateway")
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err = client.Post("http://"+addr+"/api/v1/hook", "application/json", strings.NewReader(`{}`))
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("the try took %s, want the listen table read instead of a connect", elapsed)
	}
	if !errors.Is(err, errManagedGatewayPeerUnverified) || errors.Is(err, errManagedGatewayNotRunning) || !gatewayRestartShaped(err) {
		t.Fatalf("err = %v, want a retryable peer refusal while the service runs", err)
	}
}

func TestTCPTableListensOn(t *testing.T) {
	port := uint16(18970)
	wirePort := uint32(bits.ReverseBytes16(port))
	loopback := uint32(127) | 1<<24
	rows := []mibTCPRowOwnerPID{
		{State: mibTCPStateEstab, LocalAddr: loopback, LocalPort: wirePort},
		{State: mibTCPStateListen, LocalAddr: loopback, LocalPort: uint32(bits.ReverseBytes16(port + 1))},
	}
	if tcpTableListensOn(rows, [4]byte{127, 0, 0, 1}, port) {
		t.Fatal("an established row or another port counted as a listener")
	}
	rows = append(rows, mibTCPRowOwnerPID{State: mibTCPStateListen, LocalAddr: 0, LocalPort: wirePort})
	if !tcpTableListensOn(rows, [4]byte{127, 0, 0, 1}, port) {
		t.Fatal("a listener on every address was not found")
	}
	if !tcpTableListensOn([]mibTCPRowOwnerPID{{State: mibTCPStateListen, LocalAddr: loopback, LocalPort: wirePort}}, [4]byte{127, 0, 0, 1}, port) {
		t.Fatal("a loopback listener was not found")
	}
}

func TestTCP6TableListensOnPortAtAnyAddress(t *testing.T) {
	port := uint32(bits.ReverseBytes16(18970))
	rows := []mibTCP6RowOwnerPID{{State: mibTCPStateEstab, LocalPort: port}}
	if tcp6TableListensOn(rows, 18970) {
		t.Fatal("established IPv6 row counted as a listener")
	}
	rows = append(rows, mibTCP6RowOwnerPID{State: mibTCPStateListen, LocalPort: port})
	if !tcp6TableListensOn(rows, 18970) {
		t.Fatal("IPv6 listener on the gateway port was missed")
	}
	if tcp6TableListensOn(rows, 18971) {
		t.Fatal("IPv6 listener matched another port")
	}
}

// A dual-stack listener on [::] keeps the gateway from binding 127.0.0.1, so
// the IPv6 table counts for a stopped service's IPv4 gateway address.
func TestManagedGatewayPortListeningSeesIPv6Listener(t *testing.T) {
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	listening, known := managedGatewayPortListening(net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if !known || !listening {
		t.Fatalf("IPv6 listener on port %d: listening=%t known=%t", port, listening, known)
	}
}

// A running service with no IPv4 listener has not bound its port yet, even
// when another process listens on the port over IPv6 only: the hook dials
// tcp4, so that is a peer failure the restart loop may retry, never an
// outage an open fail mode lets through.
func TestRunningManagedGatewayServiceNeedsAnIPv4Listener(t *testing.T) {
	managedTransportTestMu.Lock()
	defer managedTransportTestMu.Unlock()

	listener := listenManagedTransportTest(t)
	defer listener.Close()
	bytesRead := acceptManagedTransportBytes(t, listener)
	addr := listener.Addr().String()
	running := func(string) (uint32, error) { return 202, nil }
	restoreManagedTransportSeams(t, running, func(net.Conn) (uint32, error) { return 202, nil })
	previousListening, previousIPv4 := managedEnterpriseListening, managedEnterpriseListeningIPv4
	t.Cleanup(func() { managedEnterpriseListening, managedEnterpriseListeningIPv4 = previousListening, previousIPv4 })
	managedEnterpriseListening = func(string) (bool, bool) { return true, true }
	managedEnterpriseListeningIPv4 = func(string) (bool, bool) { return false, true }

	client, err := managedEnterpriseHTTPClient(time.Second, addr, "DefenseClawGateway")
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Post("http://"+addr+"/api/v1/hook", "application/json", strings.NewReader(`{"secret":"must-not-leak"}`))
	if err == nil || !errors.Is(err, errManagedGatewayPeerUnverified) || !errors.Is(err, errGatewayNotConnected) {
		t.Fatalf("err = %v, want a peer failure for a service without an IPv4 listener", err)
	}
	open := Options{ManagedEnterprise: true, SecureClient: true, FailMode: "open"}
	if ManagedOutageFailsOpen(open, err) {
		t.Fatalf("an open fail mode let a running service without an IPv4 listener through: %v", err)
	}
	_ = listener.Close()
	if got := <-bytesRead; len(got) != 0 {
		t.Fatalf("the listener received %d request bytes: %q", len(got), got)
	}
}

// A stopped gateway service is an outage only when nothing listens on its
// port: another process on the port, or a listen table that cannot be read,
// is an integrity failure that no fail mode lets through.
func TestStoppedManagedGatewayServiceWithAPortListenerIsNotAnOutage(t *testing.T) {
	managedTransportTestMu.Lock()
	defer managedTransportTestMu.Unlock()

	listener := listenManagedTransportTest(t)
	defer listener.Close()
	bytesRead := acceptManagedTransportBytes(t, listener)
	addr := listener.Addr().String()
	stopped := func(string) (uint32, error) {
		return 0, fmt.Errorf("%w (state=1 pid=0)", errManagedGatewayNotRunning)
	}
	restoreManagedTransportSeams(t, stopped, func(net.Conn) (uint32, error) { return 202, nil })
	previousListening := managedEnterpriseListening
	t.Cleanup(func() { managedEnterpriseListening = previousListening })
	open := Options{ManagedEnterprise: true, ManagedStandalone: true, FailMode: "open"}

	for _, tc := range []struct {
		name       string
		listening  bool
		known      bool
		notRunning bool
		portHeld   bool
	}{
		{name: "another process holds the port", listening: true, known: true, portHeld: true},
		{name: "listen table unreadable", known: false},
		{name: "nothing listens", known: true, notRunning: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			managedEnterpriseListening = func(string) (bool, bool) { return tc.listening, tc.known }
			client, err := managedEnterpriseHTTPClient(time.Second, addr, "DefenseClawGateway")
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Post("http://"+addr+"/api/v1/hook", "application/json", strings.NewReader(`{"secret":"must-not-leak"}`))
			if err == nil || !errors.Is(err, errManagedGatewayPeerUnverified) {
				t.Fatalf("err = %v, want a peer failure", err)
			}
			if got := errors.Is(err, errManagedGatewayNotRunning); got != tc.notRunning {
				t.Fatalf("not running = %v, want %v (err %v)", got, tc.notRunning, err)
			}
			if got := errors.Is(err, errManagedGatewayPortHeld); got != tc.portHeld {
				t.Fatalf("port held = %v, want %v (err %v)", got, tc.portHeld, err)
			}
			if got := ManagedOutageFailsOpen(open, err); got != tc.notRunning {
				t.Fatalf("ManagedOutageFailsOpen = %v, want %v (err %v)", got, tc.notRunning, err)
			}
		})
	}
	_ = listener.Close()
	if got := <-bytesRead; len(got) != 0 {
		t.Fatalf("the listener received %d request bytes: %q", len(got), got)
	}
}
