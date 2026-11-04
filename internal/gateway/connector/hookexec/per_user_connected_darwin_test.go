// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package hookexec

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestPerUserDarwinWaitsForAcceptedSameAccountSocket(t *testing.T) {
	reads := 0
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := awaitPerUserDarwinSocket(ctx, func(context.Context) (bool, error) {
		reads++
		return reads == 3, nil
	})
	if err != nil || reads != 3 {
		t.Fatalf("accepted same-account socket: reads=%d err=%v", reads, err)
	}
}

func TestPerUserDarwinNeverAcceptsAnUnprovenPeer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	if err := awaitPerUserDarwinSocket(ctx, func(context.Context) (bool, error) {
		return false, nil
	}); err == nil {
		t.Fatal("missing connected tuple was accepted")
	}
	reads := 0
	if err := awaitPerUserDarwinSocket(context.Background(), func(context.Context) (bool, error) {
		reads++
		return false, errors.New("inspection failed")
	}); err == nil || reads != 1 {
		t.Fatalf("inspection failure was not terminal: reads=%d err=%v", reads, err)
	}
}

func acceptedDarwinLoopbackPair(t *testing.T, network string, ip net.IP) (*net.TCPConn, *net.TCPConn, *net.TCPListener) {
	t.Helper()
	listener, err := net.ListenTCP(network, &net.TCPAddr{IP: ip})
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.DialTCP(network, nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	accepted, err := listener.AcceptTCP()
	if err != nil {
		client.Close()
		listener.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		accepted.Close()
		client.Close()
		listener.Close()
	})
	return client, accepted, listener
}

func TestPerUserDarwinVerifiesARealAcceptedSocket(t *testing.T) {
	for _, tc := range []struct {
		name, network string
		ip            net.IP
	}{
		{"IPv4", "tcp4", net.IPv4(127, 0, 0, 1)},
		{"IPv6", "tcp6", net.IPv6loopback},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, _, listener := acceptedDarwinLoopbackPair(t, tc.network, tc.ip)
			local := client.LocalAddr().(*net.TCPAddr)
			server := client.RemoteAddr().(*net.TCPAddr)
			if err := verifyPerUserConnectedTuple(local, server); err != nil {
				t.Fatalf("same-account accepted socket was not proven: %v", err)
			}
			if pid, ok := perUserConnectedPeerPID(local, server); !ok || pid != os.Getpid() {
				t.Fatalf("connected peer = %d, %v; want this process", pid, ok)
			}
			owners, ok := perUserListenerOwners(context.Background(), listener.Addr().(*net.TCPAddr))
			if !ok || len(owners) != 1 || owners[0].pid != os.Getpid() {
				t.Fatalf("listener owners = %+v, %v; want this process", owners, ok)
			}
			other := *local
			other.Port++
			ownersPID, err := darwinSocketOwnerPIDs(context.Background(), server, &other, darwinTCPEstablished)
			if err != nil || len(ownersPID) != 0 {
				t.Fatalf("another tuple has owners %v, err=%v", ownersPID, err)
			}
		})
	}
}

// The kernel accounts completed child processes in RUSAGE_CHILDREN. This
// test covers the real accepted-socket check and the peer-record lookup.
func TestPerUserDarwinConnectedCheckDoesNotSpawn(t *testing.T) {
	client, _, _ := acceptedDarwinLoopbackPair(t, "tcp4", net.IPv4(127, 0, 0, 1))
	var before, after syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_CHILDREN, &before); err != nil {
		t.Fatal(err)
	}
	if err := verifyPerUserConnectedTuple(client.LocalAddr().(*net.TCPAddr), client.RemoteAddr().(*net.TCPAddr)); err != nil {
		t.Fatal(err)
	}
	if _, ok := perUserConnectedPeerPID(client.LocalAddr().(*net.TCPAddr), client.RemoteAddr().(*net.TCPAddr)); !ok {
		t.Fatal("connected peer process was not found")
	}
	if err := syscall.Getrusage(syscall.RUSAGE_CHILDREN, &after); err != nil {
		t.Fatal(err)
	}
	if before.Utime != after.Utime || before.Stime != after.Stime {
		t.Fatalf("connected peer check used child CPU: before=%v/%v after=%v/%v",
			before.Utime, before.Stime, after.Utime, after.Stime)
	}
}
