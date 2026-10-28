// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package hookexec

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestPerUserDarwinWaitsForAcceptedSameAccountSocket(t *testing.T) {
	client := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 55233}
	server := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 18970}
	want := fmt.Sprintf("p4242\nu%d\nn127.0.0.1:18970->127.0.0.1:55233\n", os.Geteuid())
	reads := 0
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := awaitPerUserDarwinSocket(ctx, client, server, func(context.Context) ([]byte, error) {
		reads++
		if reads < 3 {
			return nil, nil // connect returned before the gateway accepted
		}
		return []byte(want), nil
	})
	if err != nil || reads != 3 {
		t.Fatalf("accepted same-account socket: reads=%d err=%v", reads, err)
	}
}

func TestPerUserDarwinNeverAcceptsAnUnprovenPeer(t *testing.T) {
	client := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 55233}
	server := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 18970}
	wrongTuple := fmt.Sprintf("p4242\nu%d\nn127.0.0.1:18970->127.0.0.1:55234\n", os.Geteuid())
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	if err := awaitPerUserDarwinSocket(ctx, client, server, func(context.Context) ([]byte, error) {
		return []byte(wrongTuple), nil
	}); err == nil {
		t.Fatal("another connected tuple was accepted")
	}
	reads := 0
	if err := awaitPerUserDarwinSocket(context.Background(), client, server, func(context.Context) ([]byte, error) {
		reads++
		return nil, errors.New("inspection failed")
	}); err == nil || reads != 1 {
		t.Fatalf("inspection failure was not terminal: reads=%d err=%v", reads, err)
	}
	foreign := fmt.Sprintf("p4242\nu%d\nn127.0.0.1:18970->127.0.0.1:55233\n", os.Geteuid()+1)
	reads = 0
	if err := awaitPerUserDarwinSocket(context.Background(), client, server, func(context.Context) ([]byte, error) {
		reads++
		return []byte(foreign), nil
	}); err == nil || reads != 1 {
		t.Fatalf("foreign owner was not refused immediately: reads=%d err=%v", reads, err)
	}
}

func TestPerUserDarwinRetriesLsofNoMatchesExit(t *testing.T) {
	missing := exec.Command("/usr/bin/false").Run()
	if missing == nil {
		t.Fatal("failed to make an lsof no-matches exit")
	}
	client := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 55233}
	server := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 18970}
	want := fmt.Sprintf("p4242\nu%d\nn127.0.0.1:18970->127.0.0.1:55233\n", os.Geteuid())
	reads := 0
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := awaitPerUserDarwinSocket(ctx, client, server, func(context.Context) ([]byte, error) {
		reads++
		if reads == 1 {
			return nil, missing
		}
		return []byte(want), nil
	}); err != nil || reads != 2 {
		t.Fatalf("lsof no-match exit was not retried: reads=%d err=%v", reads, err)
	}
}

func TestPerUserDarwinVerifiesARealAcceptedSocket(t *testing.T) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	accepted := make(chan *net.TCPConn, 1)
	go func() {
		peer, _ := listener.AcceptTCP()
		accepted <- peer
	}()
	server := <-accepted
	if server == nil {
		t.Fatal("local server did not accept")
	}
	defer server.Close()
	if err := verifyPerUserConnectedTuple(client.LocalAddr().(*net.TCPAddr), client.RemoteAddr().(*net.TCPAddr)); err != nil {
		t.Fatalf("same-account accepted socket was not proven: %v", err)
	}
}
