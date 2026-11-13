// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package peerbroker

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func runningAsLocalSystem(t *testing.T) bool {
	t.Helper()
	return requireLocalSystem() == nil
}

// loopbackPair returns the server end of a fresh loopback connection.
func loopbackPair(t *testing.T) net.Conn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server := <-accepted
	if server == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { _ = server.Close() })
	return server
}

// TestClientLookupWithoutBrokerIsUnavailableFast: no broker pipe = refused
// quickly with ErrUnavailable (the gateway then refuses the caller).
func TestClientLookupWithoutBrokerIsUnavailableFast(t *testing.T) {
	conn := loopbackPair(t)
	client, err := NewClient("DefenseClawCertGateway_00000000fe")
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err = client.Lookup(context.Background(), conn.LocalAddr().(*net.TCPAddr), conn.RemoteAddr().(*net.TCPAddr))
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Lookup = %v; want ErrUnavailable", err)
	}
	if elapsed := time.Since(started); elapsed > OperationTimeout {
		t.Fatalf("an absent broker took %s to refuse", elapsed)
	}
}

// TestClientRefusesAPipeSquatter: while the guardian is down any account
// can create a pipe with the broker name; the client must refuse a server
// that is not LocalSystem and never send it the request.
func TestClientRefusesAPipeSquatter(t *testing.T) {
	if runningAsLocalSystem(t) {
		t.Skip("the squatter must be an ordinary account")
	}
	names, err := NamesFor("DefenseClawCertGateway_00000000fd")
	if err != nil {
		t.Fatal(err)
	}
	name, _ := windows.UTF16PtrFromString(names.Pipe)
	pipe, err := windows.CreateNamedPipe(name, windows.PIPE_ACCESS_DUPLEX, windows.PIPE_TYPE_MESSAGE|windows.PIPE_READMODE_MESSAGE|windows.PIPE_WAIT, 1, MaxMessageBytes, MaxMessageBytes, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(pipe)
	got := make(chan int, 1)
	go func() {
		_ = windows.ConnectNamedPipe(pipe, nil)
		buffer := make([]byte, MaxMessageBytes)
		var n uint32
		_ = windows.ReadFile(pipe, buffer, &n, nil)
		got <- int(n)
	}()
	conn := loopbackPair(t)
	client, _ := NewClient(names.Gateway)
	_, err = client.Lookup(context.Background(), conn.LocalAddr().(*net.TCPAddr), conn.RemoteAddr().(*net.TCPAddr))
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Lookup against a squatter = %v; want ErrUnavailable", err)
	}
	select {
	case n := <-got:
		if n != 0 {
			t.Fatalf("the squatter received %d request bytes", n)
		}
	case <-time.After(3 * time.Second):
	}
}

// TestNewServerRequiresLocalSystem: the broker never starts as an ordinary
// account.
func TestNewServerRequiresLocalSystem(t *testing.T) {
	if runningAsLocalSystem(t) {
		t.Skip("running as LocalSystem")
	}
	if _, err := NewServer("DefenseClawGateway", nil); err == nil {
		t.Fatal("NewServer started as an ordinary account")
	}
}

// TestLoopbackClientOwnerNamesThisProcess: the gateway side reads the PID
// and creation time of the client end from the owner-module table.
func TestLoopbackClientOwnerNamesThisProcess(t *testing.T) {
	conn := loopbackPair(t)
	owner, err := clientOwnerForTest(conn)
	if err != nil {
		t.Fatal(err)
	}
	if owner.PID != windows.GetCurrentProcessId() || owner.CreateTime == 0 {
		t.Fatalf("owner = %+v; want this process with a creation time", owner)
	}
}
