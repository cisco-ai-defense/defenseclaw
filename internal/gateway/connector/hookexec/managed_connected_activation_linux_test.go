// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// A socket-activated gateway: PID 1 holds the listener, so the client's
// connect() succeeds while the unit is still starting and systemd reports
// MainPID 0. The managed client must wait for the verified service within the
// request deadline, send no HTTP bytes until it is verified, and then answer
// (GAP-1138). It used to refuse such a connection at once.
func TestManagedEnterpriseClientWaitsForASocketActivatedGateway(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var started atomic.Bool
	previous := managedLinuxServiceShow
	managedLinuxServiceShow = func(context.Context) ([]byte, error) {
		pid := 0
		if started.Load() {
			pid = os.Getpid()
		}
		return []byte(fmt.Sprintf("MainPID=%d\nExecStart={ path=%s ; argv[]=%s ; ignore_errors=no }\nUser=%d\nUID=%d\n",
			pid, managedLinuxGatewayExecutable, managedLinuxGatewayExecutable, os.Geteuid(), os.Geteuid())), nil
	}
	t.Cleanup(func() { managedLinuxServiceShow = previous })

	served := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			served <- err
			return
		}
		defer conn.Close()
		// While the unit is starting, nothing may arrive.
		_ = conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
		var first [1]byte
		n, err := conn.Read(first[:])
		var timeout net.Error
		if n != 0 || !errors.As(err, &timeout) || !timeout.Timeout() {
			served <- fmt.Errorf("the client sent %d bytes (%v) before the gateway was verified", n, err)
			return
		}
		started.Store(true)
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		request, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			served <- err
			return
		}
		_ = request.Body.Close()
		_, err = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
		served <- err
	}()

	client, err := managedEnterpriseHTTPClient(10*time.Second, listener.Addr().String(), managedLinuxGatewayService)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Get("http://" + listener.Addr().String() + "/health")
	if err != nil {
		t.Fatalf("a socket-activated gateway that started within the request deadline was refused: %v", err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if serveErr := <-served; serveErr != nil {
		t.Fatal(serveErr)
	}
	if string(body) != "ok" {
		t.Fatalf("gateway answer = %q", body)
	}
}
