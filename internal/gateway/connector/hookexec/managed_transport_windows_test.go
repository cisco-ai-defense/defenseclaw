// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
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
	if got := managedPeerFailureReason(err); got != managedGatewayPortHeldReason {
		t.Fatalf("foreign listener reason = %q, want %q", got, managedGatewayPortHeldReason)
	}
	if got := <-bytesRead; len(got) != 0 {
		t.Fatalf("foreign listener received %d request bytes: %q", len(got), got)
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

// A real IPv6 listener on the port is seen through the live owner-PID table.
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

func stubManagedTransportListening(t *testing.T, listening, known bool) {
	t.Helper()
	old := managedEnterpriseListening
	managedEnterpriseListening = func(string) (bool, bool) { return listening, known }
	t.Cleanup(func() {
		managedTransportTestMu.Lock()
		defer managedTransportTestMu.Unlock()
		managedEnterpriseListening = old
	})
}

func stoppedManagedGatewaySeams(t *testing.T) *bool {
	t.Helper()
	dialed := false
	restoreManagedTransportSeams(t,
		func(string) (uint32, error) {
			return 0, fmt.Errorf("%w (state=1 pid=0)", errManagedGatewayNotRunning)
		},
		func(net.Conn) (uint32, error) { return 0, errors.New("must not resolve a connection") },
	)
	originalDial := managedEnterpriseDialContext
	managedEnterpriseDialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		dialed = true
		return originalDial(ctx, network, address)
	}
	t.Cleanup(func() {
		managedTransportTestMu.Lock()
		defer managedTransportTestMu.Unlock()
		managedEnterpriseDialContext = originalDial
	})
	return &dialed
}

// A stopped gateway service is "not running" only when nothing listens on
// its port. Another listener, or a listen table the hook cannot read, keeps
// the peer failure closed.
func TestManagedEnterpriseTransportStoppedServiceClassifiesListenerBeforeDial(t *testing.T) {
	for _, tc := range []struct {
		name             string
		listening, known bool
		wantReason       string
		wantNotRunning   bool
	}{
		{name: "port free", known: true, wantReason: managedGatewayNotRunningReason, wantNotRunning: true},
		{name: "port held", listening: true, known: true, wantReason: managedGatewayPortHeldReason},
		{name: "table unreadable", wantReason: managedGatewayPeerUnverifiedReason},
	} {
		t.Run(tc.name, func(t *testing.T) {
			managedTransportTestMu.Lock()
			defer managedTransportTestMu.Unlock()
			dialed := stoppedManagedGatewaySeams(t)
			stubManagedTransportListening(t, tc.listening, tc.known)

			client, err := managedEnterpriseHTTPClient(time.Second, "127.0.0.1:18970", "DefenseClawGateway")
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Post("http://127.0.0.1:18970/api/v1/hook", "application/json", strings.NewReader(`{}`))
			if !errors.Is(err, errManagedGatewayPeerUnverified) {
				t.Fatalf("stopped service error = %v, want a peer failure", err)
			}
			if got := managedPeerFailureReason(err); got != tc.wantReason {
				t.Fatalf("reason = %q, want %q (err=%v)", got, tc.wantReason, err)
			}
			if got := managedPeerFailMode("open", err) == "open"; got != tc.wantNotRunning {
				t.Fatalf("open mode allowed = %t, want %t (err=%v)", got, tc.wantNotRunning, err)
			}
			if *dialed {
				t.Fatal("stopped service still dialed the gateway port")
			}
		})
	}
}

// A managed hook whose gateway service is stopped, with nothing else on its
// port, follows its fail mode: the Secure Client default allows and an
// explicit closed mode blocks. Another process on the port blocks in both.
func TestManagedEnterpriseRunStoppedGatewayFollowsFailMode(t *testing.T) {
	for _, tc := range []struct {
		failMode   string
		listening  bool
		wantCode   int
		wantReason string
	}{
		{failMode: "open", wantCode: 0, wantReason: managedGatewayNotRunningReason},
		{failMode: "closed", wantCode: blockExit, wantReason: managedGatewayNotRunningReason},
		{failMode: "open", listening: true, wantCode: blockExit, wantReason: managedGatewayPortHeldReason},
	} {
		t.Run(fmt.Sprintf("%s/listening=%t", tc.failMode, tc.listening), func(t *testing.T) {
			managedTransportTestMu.Lock()
			defer managedTransportTestMu.Unlock()
			stoppedManagedGatewaySeams(t)
			stubManagedTransportListening(t, tc.listening, true)

			home := t.TempDir()
			token := "authenticated-token"
			var out, errb bytes.Buffer
			code := Run(context.Background(), Options{
				Connector:                 "claudecode",
				Event:                     "PreToolUse",
				APIAddr:                   "127.0.0.1:18970",
				Home:                      home,
				HookDir:                   filepath.Join(home, "hooks"),
				FailMode:                  tc.failMode,
				ManagedEnterprise:         true,
				ManagedGatewayServiceName: "DefenseClawGateway",
				AuthenticatedManagedToken: &token,
				Stdin:                     strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Bash"}`),
				Stdout:                    &out,
				Stderr:                    &errb,
			})
			if code != tc.wantCode {
				t.Fatalf("code = %d, want %d; stdout=%q stderr=%q", code, tc.wantCode, out.String(), errb.String())
			}
			if !strings.Contains(errb.String(), tc.wantReason) {
				t.Fatalf("stderr = %q, want %q", errb.String(), tc.wantReason)
			}
		})
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

// A service security descriptor that denies the user a status query is
// permission drift: the hook follows its fail mode instead of failing closed,
// reports its own reason, and never dials the port.
func TestManagedEnterpriseTransportUnreadableServiceFollowsFailMode(t *testing.T) {
	managedTransportTestMu.Lock()
	defer managedTransportTestMu.Unlock()
	restoreManagedTransportSeams(t,
		func(string) (uint32, error) { return 0, windows.ERROR_ACCESS_DENIED },
		func(net.Conn) (uint32, error) { return 0, errors.New("must not resolve a connection") },
	)
	client, err := managedEnterpriseHTTPClient(time.Second, "127.0.0.1:18970", "DefenseClawGateway")
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Post("http://127.0.0.1:18970/api/v1/hook", "application/json", strings.NewReader(`{}`))
	if !errors.Is(err, errManagedGatewayPeerUnverified) || !errors.Is(err, errManagedGatewayServiceUnreadable) {
		t.Fatalf("unreadable service error = %v", err)
	}
	if got := managedPeerFailureReason(err); got != managedGatewayServiceUnreadableReason {
		t.Fatalf("reason = %q", got)
	}
	if managedPeerFailMode("open", err) != "open" || managedPeerFailMode("closed", err) != "closed" {
		t.Fatal("unreadable service did not follow the hook's fail mode")
	}
}
